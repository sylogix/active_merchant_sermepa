# encoding: utf-8
module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    module Integrations #:nodoc:
      module Sermepa
        # Sermepa/Servired Spanish Virtual POS Gateway
        #
        # Support for the Spanish payment gateway provided by Sermepa, part of Servired,
        # one of the main providers in Spain to Banks and Cajas.
        #
        # Requires the :terminal_id, :commercial_id, and :secret_key to be set in the credentials
        # before the helper can be used. Credentials may be overwriten when instantiating the helper
        # if required or instead of the global variable. Optionally, the :key_type can also be set to
        # either 'sha1_complete' or 'sha1_extended', where the later is the default case. This
        # is a configurable option in the Sermepa admin which you may or may not be able to access.
        # If nothing seems to work, try changing this.
        #
        # Ensure the gateway is configured correctly. Synchronization should be set to Asynchronous
        # and the parameters in URL option (Parámetros en las URLs) should be set to true unless
        # the notify_url is provided. During development on localhost ensuring this option is set
        # is especially important as there is no other way to confirm a successful purchase.
        #
        # Your view for a payment form might look something like the following:
        #
        #   <%= payment_service_for @transaction.id, 'Company name', :amount => @transaction.amount, :currency => 'EUR', :service => :sermepa do |service| %>
        #     <% service.description     @sale.description %>
        #     <% service.customer_name   @sale.client.name %>
        #     <% service.notify_url      notify_sale_url(@sale) %>
        #     <% service.success_url     win_sale_url(@sale) %>
        #     <% service.failure_url     fail_sale_url(@sale) %>
        #
        #     <%= submit_tag "PAY!" %>
        #   <% end %>
        #
        #
        #
        class Helper < ActiveMerchant::Billing::Integrations::Helper
          include PostsData

          SHA256_SIGNATURE_VERSION = 'HMAC_SHA256_V1'
          attr_reader :fields_sha256

          class << self
            # Credentials should be set as a hash containing the fields:
            #  :terminal_id, :commercial_id, :secret_key, :key_type (optional)
            attr_accessor :credentials

            def encrypt(key, data)
              return if data.nil?
              block_length = 8
              cipher = OpenSSL::Cipher::Cipher.new('DES3')
              cipher.encrypt

              cipher.key = Base64.strict_decode64(key)
              # http://apidock.com/ruby/v1_9_3_392/Base64/strict_decode64
              # cipher.key = key.unpack("m0").first

              # The OpenSSL default of an all-zeroes ("\\0") IV is used.
              cipher.padding = 0

              # Padding must be done with zeros
              data += "\0" until data.bytesize % block_length == 0 #Pad with zeros
              #data += '\u0000' until data.bytesize % block_length == 0 #Pad with zeros
              output = cipher.update(data)
              output << cipher.final
              output
            end

            def mac256(key, data)
              return if data.nil?
              OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), key, data)
            end
          end

          mapping :account,     'Ds_Merchant_MerchantName'

          mapping :currency,    'Ds_Merchant_Currency'
          mapping :amount,      'Ds_Merchant_Amount'

          mapping :order,       'Ds_Merchant_Order'
          mapping :description, 'Ds_Merchant_ProductDescription'
          mapping :client,      'Ds_Merchant_Titular'

          mapping :notify_url,  'Ds_Merchant_MerchantURL'
          mapping :success_url, 'Ds_Merchant_UrlOK'
          mapping :failure_url, 'Ds_Merchant_UrlKO'

          mapping :language,    'Ds_Merchant_ConsumerLanguage'

          mapping :transaction_type, 'Ds_Merchant_TransactionType'

          mapping :customer_name, 'Ds_Merchant_Titular'

          mapping :sum_total,   'Ds_Merchant_SumTotal'
          mapping :frequency,   'Ds_Merchant_DateFrecuency'
          mapping :expiry_date, 'Ds_Merchant_ChargeExpiryDate'

          #### Special Request Specific Fields ####
          # SHA256 signature version
          mapping :signature_version, 'Ds_SignatureVersion'
          mapping :parameters,        'Ds_MerchantParameters'
          mapping :signature,         'Ds_Signature'
          ########

          # ammount should always be provided in cents!
          def initialize(order, account, options = {})
            self.credentials = options.delete(:credentials) if options[:credentials]
            super(order, account, options)
            @fields_sha256 = {}

            add_field 'Ds_Merchant_MerchantCode', credentials[:commercial_id]
            add_field 'Ds_Merchant_Terminal', credentials[:terminal_id]
            add_field mappings[:transaction_type], '0' # Default Transaction Type
            self.transaction_type = '0'
          end

          def add_field_sha256(name, value)
            return if name.blank? || value.blank?
            fields_sha256[name.to_s] = value.to_s
          end

          # Allow credentials to be overwritten if needed
          def credentials
            @credentials || self.class.credentials
          end
          def credentials=(creds)
            @credentials = (self.class.credentials || {}).dup.merge(creds)
          end

          def amount=(money)
            cents = money.respond_to?(:cents) ? money.cents : money
            if money.is_a?(String) || cents.to_i <= 0
              raise ArgumentError, 'money amount must be either a Money object or a positive integer in cents.'
            end
            add_field mappings[:amount], cents.to_i
          end

          def order=(order_id)
            order_id = order_id.to_s
            if order_id !~ /^[0-9]{4}/ && order_id.length <= 8
              order_id = ('0' * 4) + order_id
            end
            regexp = /^[0-9]{4}[0-9a-zA-Z]{0,8}$/
            raise "Invalid order number format! First 4 digits must be numbers" if order_id !~ regexp
            add_field mappings[:order], order_id
          end

          def currency=(value)
            add_field mappings[:currency], Sermepa.currency_code('978')
          end

          def language(lang)
            add_field mappings[:language], Sermepa.language_code('001')
          end

          def transaction_type(type)
            add_field mappings[:transaction_type], Sermepa.transaction_code('0')
          end

          def form_fields
            parameters = encode_merchant_parameters
            add_field_sha256 mappings[:signature_version], SHA256_SIGNATURE_VERSION
            add_field_sha256 mappings[:parameters], parameters
            add_field_sha256 mappings[:signature], sign_request(parameters)
            @fields_sha256
          end


          # Send a manual request for the currently prepared transaction.
          # This is an alternative to the normal view helper and is useful
          # for special types of transaction.
          def send_transaction
            body = build_xml_request

            headers = { }
            headers['Content-Length'] = body.size.to_s
            headers['User-Agent'] = "Active Merchant -- http://activemerchant.org"
            headers['Content-Type'] = 'application/x-www-form-urlencoded'

            # Return the raw response data
            ssl_post(Sermepa.operations_url, "entrada="+CGI.escape(body), headers)
          end

          protected

          def build_xml_request
            xml = Builder::XmlMarkup.new
            xml.instruct!
            xml.REQUEST do
              build_merchant_data(xml)
              xml.DS_SIGNATUREVERSION SHA256_SIGNATURE_VERSION
              xml.DS_SIGNATURE sign_request(merchant_data_xml)
            end
            xml.target!
          end

          def build_merchant_data(xml)
            xml.DATOSENTRADA do
              xml.DS_MERCHANT_CURRENCY @fields['Ds_Merchant_Currency']
              xml.DS_MERCHANT_AMOUNT @fields['Ds_Merchant_Amount']
              xml.DS_MERCHANT_MERCHANTURL @fields['Ds_Merchant_MerchantURL']
              xml.DS_MERCHANT_TRANSACTIONTYPE @fields['Ds_Merchant_TransactionType']
              xml.DS_MERCHANT_MERCHANTDATA @fields['Ds_Merchant_ProductDescription']
              xml.DS_MERCHANT_TERMINAL credentials[:terminal_id]
              xml.DS_MERCHANT_MERCHANTCODE credentials[:commercial_id]
              xml.DS_MERCHANT_ORDER @fields['Ds_Merchant_Order']
            end
          end

          def merchant_data_xml
            xml = Builder::XmlMarkup.new
            build_merchant_data(xml)
            xml.target!
          end

          # Transform all current fields to a json object and apply base64 encoding without new lines.
          def encode_merchant_parameters
            # Base64.urlsafe_encode64(fields.to_json)
            # http://apidock.com/ruby/Base64/urlsafe_encode64
            Base64.strict_encode64(fields.to_json).tr("+/", "-_")
          end

          # Generate a signature authenticating the current request.
          def sign_request(data)
            key = self.class.encrypt(credentials[:secret_key], fields['Ds_Merchant_Order'])
            Base64.strict_encode64(self.class.mac256(key, data))
          end
        end
      end
    end
  end
end
