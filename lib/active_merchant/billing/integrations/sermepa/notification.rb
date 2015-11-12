# encoding: utf-8
module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    module Integrations #:nodoc:
      module Sermepa
        class Notification < ActiveMerchant::Billing::Integrations::Notification
          include PostsData

          def complete?
            status == 'Completed'
          end

          def transaction_id
            params['ds_order']
          end

          # When was this payment received by the client.
          def received_at
            if params['ds_date']
              (day, month, year) = params['ds_date'].split('/')
              Time.parse("#{year}-#{month}-#{day} #{params['ds_hour']}")
            else
              Time.now # Not provided!
            end
          end

          # the money amount we received in cents in X.2 format
          def gross
            sprintf("%.2f", gross_cents / 100.0)
          end

          def gross_cents
            params['ds_amount'].to_i
          end

          # Was this a test transaction?
          def test?
            false
          end

          def currency
            Sermepa.currency_from_code(params['ds_currency'])
          end

          # Status of transaction. List of possible values:
          # <tt>Completed</tt>
          # <tt>Failed</tt>
          # <tt>Pending</tt>
          def status
            return 'Failed' if error_code
            case response.to_i
            when 0..99
              'Completed'
            when 900
              'Pending'
            else
              'Failed'
            end
          end

          def error_code
            params['ds_errorcode']
          end

          def response
            params['ds_response']
          end

          def error_message
            msg = Sermepa.response_code_message(response)
            response.to_s + ' - ' + (msg.nil? ? 'Operación Aceptada' : msg)
          end

          def secure_payment?
            params['ds_securepayment'] == '1'
          end

          # Acknowledge the transaction.
          #
          # Validate the details provided by the gateway by ensuring that the signature
          # matches up with the details provided.
          #
          # Optionally, a set of credentials can be provided that should contain a
          # :secret_key instead of using the global credentials defined in the Sermepa::Helper.
          #
          # Example:
          #
          #   def notify
          #     notify = Sermepa::Notification.new(request.query_parameters)
          #
          #     if notify.acknowledge
          #       ... process order ... if notify.complete?
          #     else
          #       ... log possible hacking attempt ...
          #     end
          #
          #
          def acknowledge(credentials = nil)
            if raw =~ /<retornoxml>/i
              acknowledge_xml(credentials)
            else
              acknowledge_params(credentials)
            end
          end

          private

          def acknowledge_params(credentials)
            return if params['ds_merchantparameters'].blank?
            
            params.merge!(parse_merchant_parameters)
            # sig = Base64.urlsafe_encode64(Sermepa::Helper.mac256(get_key(credentials), params['ds_merchantparameters']))
            # http://apidock.com/ruby/Base64/urlsafe_encode64
            sig = Base64.strict_encode64(Sermepa::Helper.mac256(get_key(credentials), params['ds_merchantparameters'])).tr("+/", "-_")
            sig.upcase == params['ds_signature'].to_s.upcase
          end

          def acknowledge_xml(credentials)
            sig = Base64.strict_encode64(Sermepa::Helper.mac256(get_key(credentials), xml_signed_fields))
            sig.upcase == params['ds_signature'].to_s.upcase
          end

          def get_key(credentials)
            Sermepa::Helper.encrypt((credentials || Sermepa::Helper.credentials)[:secret_key], params['ds_order'])
          end

          # Transform all current fields to a json object and apply base64 encoding without new lines.
          def parse_merchant_parameters
            parsed = {}
            JSON.parse(decoded_merchant_parameters).each do |key, value|
              # downcase hash keys
              parsed[key.downcase] = value
            end if decoded_merchant_parameters
            parsed
          end

          def xml_signed_fields
            params['ds_amount'] + params['ds_order'] + params['ds_merchantcode'] + params['ds_currency'] +
                params['ds_response'] + params['ds_transactiontype'] + params['ds_securepayment']
          end

          def decoded_merchant_parameters
            # Base64.urlsafe_decode64(params['ds_merchantparameters'])
            # http://apidock.com/ruby/Base64/urlsafe_decode64
            # http://apidock.com/ruby/v1_9_3_392/Base64/strict_decode64
            params['ds_merchantparameters'].tr("-_", "+/").unpack("m0").first if params['ds_merchantparameters']
          end

          def xml?
            !params['code'].blank?
          end

          # Take the posted data and try to extract the parameters.
          #
          # Posted data can either be a parameters hash, XML string or CGI data string
          # of parameters.
          #
          def parse(post)
            if post.is_a?(Hash)
              @raw = post.inspect.to_s
              post.each { |key, value|  params[key.downcase] = value }
            elsif post.to_s =~ /<retornoxml>/i
              # XML source
              @raw = post.to_s
              self.params = xml_response_to_hash(raw)
            else
              @raw = post.to_s
              for line in raw.split('&')
                key, value = *line.scan( %r{^([A-Za-z0-9_.]+)\=(.*)$} ).flatten
                params[key.downcase] = CGI.unescape(value)
              end
            end
          end

          def xml_response_to_hash(xml)
            result = { }
            doc = Nokogiri::XML(xml)
            result['code'] = doc.css('RETORNOXML CODIGO').inner_text
            if result['code'] == '0'
              doc.css('RETORNOXML OPERACION').children.each do |child|
                result[child.name.downcase] = child.inner_text
              end
            else
              result['ds_errorcode'] = result['code']
              doc.css('RETORNOXML RECIBIDO DATOSENTRADA').children.each do |child|
                result[child.name.downcase] = child.inner_text unless child.name == 'text'
              end
            end
            result
          end

        end
      end
    end
  end
end
