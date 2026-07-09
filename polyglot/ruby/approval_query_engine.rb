# frozen_string_literal: true

require 'json'
require 'eth-json-rpc-transactions'
require 'web3'
require 'digest/sha256'

module ApproveWarden
  # Core constants and configuration
  class Config
    DEFAULT_RPC_URL = ENV['APPROVEWARDEN_RPC'] || 'https://mainnet.infura.io/v3/demo'
    
    # Risk thresholds (configurable)
    INFINITE_ALLOWANCE_THRESHOLD = 1_000_000_000_000_000_000.0
    HIGH_RISK_APPROVAL_COUNT = 5
    MEDIUM_RISK_SCORE = 30.0
    
    # Token metadata cache (in-memory, for demo)
    TOKEN_METADATA_CACHE = {}
    
    # Event topics for ERC-20 approvals
    ERC20_TRANSFER_TOPIC = 'Transfer'.to_s
    ERC20_APPROVAL_TOPIC = 'Approval'.to_s
    
    # Gas settings
    DEFAULT_GAS_PRICE = 15_000_000_000 # 15 gwei
    DEFAULT_GAS_LIMIT = 210_000
  end

  # Risk scoring engine
  class RiskScorer
    attr_reader :wallet_address, :total_score, :critical_issues
    
    def initialize(wallet_address)
      @wallet_address = wallet_address.to_s.downcase
      @total_score = 0.0
      @critical_issues = []
    end

    # Add points for each issue found
    def add_issue(type:, severity:, description: nil, amount: 0)
      score = case severity
        when :high then 25.0
        when :medium then 10.0
        when :low then 3.0
        else 1.0
      end
      
      @total_score += score
      @critical_issues << {
        type: type,
        severity: severity,
        description: description || "Unknown #{type} issue",
        amount: amount
      }
    end

    def critical?
      @total_score >= Config::HIGH_RISK_SCORE && !@critical_issues.empty?
    end

    def to_h
      {
        wallet_address: @wallet_address,
        total_score: @total_score.round(2),
        critical?: critical?,
        issues: @critical_issues,
        drainer_exposure_score: calculate_drainer_score
      }
    end

    private

    def calculate_drainer_score
      # Heuristic: higher score = more likely to be a drainer target
      base = (@total_score / 10.0)
      
      if @critical_issues.any? { |i| i[:severity] == :high }
        base += 50.0
      end
      
      [base, 100.0].min
    end
  end

  # ERC-20 approval scanner
  class Erc20Scanner
    def self.abi
      [
        { type: 'function', name: 'allowance', inputs: [{ name: 'owner', type: 'address' }, 
                                                          { name: 'spender', type: 'address' }], output: 'uint256' },
        { type: 'event', name: 'Approval', inputs: [{ indexed: true, name: 'owner', type: 'address' },
                                                     { indexed: true, name: 'spender', type: 'address' },
                                                     { name: 'value', type: 'uint256' }] }
      ]
    end

    def self.scan_allowance(web3, owner, spender, token_address)
      return 0 unless web3.is_contract?(token_address)
      
      allowance = web3.call_function(token_address, :allowance, [owner, spender])
      (allowance || 0).to_f
    end

    def self.detect_infinite_allowances(web3, owner, token_addresses)
      infinite = []
      
      token_addresses.each do |token|
        allowance = scan_allowance(web3, owner, owner, token)
        
        if allowance > Config::INFINITE_ALLOWANCE_THRESHOLD
          infinite << {
            token: token,
            amount: allowance,
            severity: :high
          }
        end
      end
      
      infinite
    end

    def self.scan_spender_approvals(web3, owner, spender, token_addresses)
      dangerous = []
      
      token_addresses.each do |token|
        allowance = scan_allowance(web3, owner, spender, token)
        
        if allowance > 0 && allowance < Config::INFINITE_ALLOWANCE_THRESHOLD
          # Check if this is a known high-risk spender
          risk_score = check_spender_reputation(spender, allowance)
          
          if risk_score > 15.0 || allowance > 1_000_000_000
            dangerous << {
              token: token,
              amount: allowance,
              severity: risk_score > 30 ? :high : :medium,
              spender_reputation: risk_score
            }
          end
        end
      end
      
      dangerous
    end

    private

    def self.check_spender_reputation(spender, allowance)
      # Simple heuristic: check if spender has been involved in many approvals
      # In production, this would query a reputation service like Chainlink or OpenZeppelin
      base_score = 5.0
      
      # Higher allowance = higher risk
      allowance_factor = [Math.log(allowance + 1) * 2, 30].min
      
      [base_score + allowance_factor, 50.0].min
    end
  end

  # ERC-721/1155 approval scanner
  class Erc7211155Scanner
    def self.abi_721
      [
        { type: 'function', name: 'getApproved', inputs: [{ name: 'tokenId', type: 'uint256' }], output: 'address' },
        { type: 'event', name: 'Approval', inputs: [{ indexed: true, name: 'owner', type: 'address' },
                                                     { indexed: true, name: 'approved', type: 'address' },
                                                     { indexed: false, name: 'tokenId', type: 'uint256' }] }
      ]
    end

    def self.abi_1155
      [
        { type: 'function', name: 'balanceOf', inputs: [{ name: 'account', type: 'address' }, 
                                                         { name: 'id', type: 'uint256' }], output: 'uint256' },
        { type: 'event', name: 'ApprovalForAll', inputs: [{ indexed: true, name: 'owner', type: 'address' },
                                                          { indexed: false, name: 'operator', type: 'address' },
                                                          { indexed: true, name: 'approved', type: 'bool' }] }
      ]
    end

    def self.scan_operator_approvals(web3, owner, operator_addresses)
      dangerous = []
      
      operator_addresses.each do |op|
        # Check ERC-1155 ApprovalForAll
        is_approved_all = web3.call_function(owner, :getApproved, [0]) == op
        
        if is_approved_all
          # Estimate total value at risk
          balance = 0
          token_count = 0
          
          begin
            # Sample check - in production, use proper estimation
            sample_token = 0
            while (balance = web3.call_function(owner, :balanceOf, [sample_token])) > 0
              balance += 1
              token_count += 1
              break if balance > 100 || token_count >= 50
            end
          rescue
            # Fallback estimation
            balance = 100.0
            token_count = 50
          end
          
          dangerous << {
            operator: op,
            type: :erc1155_approval_for_all,
            estimated_value: balance * 100_000_000, # rough estimate
            severity: :high
          }
        end
      end
      
      dangerous
    end

    def self.scan_single_approvals(web3, owner, token_id)
      approved = web3.call_function(owner, :getApproved, [token_id])
      
      if approved && approved != '0x0000000000000000000000000000000000000000'
        dangerous = {
          token_id: token_id,
          approved: approved,
          severity: :medium
        }
        
        # Check if this is a known malicious contract
        risk_score = check_contract_reputation(approved)
        dangerous[:severity] = :high if risk_score > 25
        
        dangerous
      end
      
      nil
    end

    private

    def self.check_contract_reputation(address)
      # Simple heuristic based on common drainer patterns
      base = 10.0
      
      # Check for common drainer prefixes (production would use full database)
      drainer_prefixes = [
        '0x7f5c', '0x8d3a', '0x9b2e', '0xa4f1'
      ]
      
      drainer_prefixes.each do |prefix|
        if address.start_with?(prefix)
          base += 20.0
          break
        end
      end
      
      [base, 50.0].min
    end
  end

  # Transaction builder for revokes
  class RevokeBuilder
    def self.build_erc20_revoke(web3, owner, spender, token_address)
      {
        to: token_address,
        value: '0',
        from: owner,
        gas_limit: Config::DEFAULT_GAS_LIMIT,
        gas_price: Config::DEFAULT_GAS_PRICE,
        data: web3.contract(token_address).function(:approve).abi_encode([owner, spender], :static) + 
               web3.contract(token_address).event('Approval').signature,
        type: 'erc20_revoke'
      }
    end

    def self.build_erc1155_approval_for_all_revoke(web3, owner, operator, token_address)
      {
        to: token_address,
        value: '0',
        from: owner,
        gas_limit: Config::DEFAULT_GAS_LIMIT * 2,
        gas_price: Config::DEFAULT_GAS_PRICE,
        data: web3.contract(token_address).function(:setApprovalForAll).abi_encode([operator, false], :static) + 
               web3.contract(token_address).event('ApprovalForAll').signature,
        type: 'erc1155_approval_for_all_revoke'
      }
    end

    def self.build_batch_revokes(web3, owner, revocations)
      batch = {
        to: owner,
        value: '0',
        from: owner,
        gas_limit: Config::DEFAULT_GAS_LIMIT * 5,
        gas_price: Config::DEFAULT_GAS_PRICE,
        type: 'batch_revoke'
      }

      revocations.each do |revoke|
        batch[:data] += revoke[:data] if revoke[:data].is_a?(String)
      end
      
      batch
    end
  end

  # Main query engine orchestrator
  class ApprovalQueryEngine
    attr_reader :web3, :owner_address
    
    def initialize(web3: Web3.new, owner_address: nil)
      @web3 = web3
      @owner_address = owner_address&.to_s.downcase || '0x0000000000000000000000000000000000000000'
    end

    # Main entry point for scanning a wallet
    def scan_wallet(token_addresses: nil)
      token_addresses ||= @web3.eth.get_token_list
      
      scanner = Scanner.new(@owner_address, @web3)
      
      result = {
        wallet_address: @owner_address,
        timestamp: Time.now.iso8601,
        network: @web3.net.name,
        scanners: {},
        summary: {}
      }

      # Run all scanners
      token_addresses.each do |token|
        next unless token.is_a?(String) && !token.start_with?('0x')
        
        begin
          erc20_results = scanner.scan_erc20(token, @owner_address)
          
          result[:scanners][:erc20] ||= []
          result[:scanners][:erc20] << erc20_results if erc20_results.any?
          
          # Track for summary
          result[:summary][:total_tokens_scanned] = (result[:summary].fetch(:total_tokens_scanned, 0) + 1)
        rescue => e
          result[:errors] ||= []
          result[:errors] << { token: token, error: e.message }
        end
      end
      
      # Calculate overall risk score
      result[:overall_risk_score] = scanner.calculate_overall_score
      
      result
    end

    def scan_single_token(token_address, owner)
      scanner = Scanner.new(owner, @web3)
      
      begin
        erc20_results = scanner.scan_erc20(token_address, owner)
        
        {
          token: token_address,
          results: erc20_results,
          timestamp: Time.now.iso8601
        }
      rescue => e
        {
          token: token_address,
          error: e.message,
          timestamp: Time.now.iso8601
        }
      end
    end

    # Get all dangerous approvals for a wallet
    def get_all_dangerous_approvals(owner)
      scanner = Scanner.new(owner, @web3)
      
      begin
        erc20_results = scanner.scan_erc20_all(owner)
        
        {
          owner: owner,
          total_issues: erc20_results.count,
          high_risk_count: erc20_results.select { |r| r[:severity] == :high }.count,
          issues: erc20_results
        }
      rescue => e
        {
          owner: owner,
          error: e.message,
          timestamp: Time.now.iso8601
        }
      end
    end

    private

    class Scanner
      def initialize(owner_address, web3)
        @owner = owner_address.to_s.downcase
        @web3 = web3
        @erc20_results = []
        @risk_scorer = RiskScorer.new(@owner)
      end

      def scan_erc20(token_address, owner)
        scanner = Erc20Scanner
        
        # Check infinite allowances first (fast path)
        infinite = scanner.detect_infinite_allowances(@web3, @owner, [token_address])
        
        if infinite.any?
          infinite.each do |issue|
            @risk_scorer.add_issue(
              type: :infinite_allowance,
              severity: issue[:severity],
              amount: issue[:amount]
            )
          end
          
          return infinite
        end
        
        # Check spender approvals (slower but more thorough)
        dangerous = scanner.scan_spender_approvals(@web3, @owner, [token_address])
        
        if dangerous.any?
          dangerous.each do |issue|
            @risk_scorer.add_issue(
              type: :dangerous_spender,
              severity: issue[:severity],
              amount: issue[:amount]
            )
          end
          
          return dangerous
        end
        
        []
      end

      def scan_erc20_all(owner)
        # Scan all ERC-20 tokens the owner has interacted with
        # In production, this would query transaction history
        scanner = Erc20Scanner
        
        # Get unique token addresses from recent transactions (demo: use common tokens)
        token_addresses = get_interacted_tokens(owner)
        
        results = []
        
        token_addresses.each do |token|
          begin
            infinite = scanner.detect_infinite_allowances(@web3, @owner, [token])
            
            if infinite.any? || (scanner.scan_spender_approvals(@web3, @owner, [token]).any?)
              results << {
                token: token,
                issues: infinite + scanner.scan_spender_approvals(@web3, @owner, [token]),
                timestamp: Time.now.iso8601
              }
            end
          rescue => e
            # Log but continue
          end
        end
        
        results
      end

      def get_interacted_tokens(owner)
        # In production: query transaction history from RPC
        # For demo: return some common tokens for testing
        
        begin
          # Try to get actual transactions
          @web3.eth.get_transactions({
            from: owner,
            limit: 100,
            includePending: true
          }) do |txs|
            txs.map { |tx| tx[:to] }.uniq.compact.select do |addr|
              # Filter to likely tokens (not EOA)
              addr.length == 42 && !['0x' + '0'.ljust(40, '0'), 
                                      '0x' + '1'.ljust(40, '0')].include?(addr)
            end
          end || []
        rescue