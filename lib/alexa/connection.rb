require "cgi"
require "base64"
require "openssl"
require "digest/sha1"
require "faraday"
require "time"

module Alexa
  class Connection
    SERVICE_HOST = "awis.amazonaws.com"
    SERVICE_ENDPOINT = "awis.us-west-1.amazonaws.com"
    SERVICE_PORT = 443
    SERVICE_URI = "/api"
    SERVICE_REGION = "us-west-1"
    SERVICE_NAME = "awis"

    attr_accessor :secret_access_key, :access_key_id
    attr_writer :params

    RFC_3986_UNRESERVED_CHARS = "-_.~a-zA-Z\\d"

    def initialize(credentials = {})
      self.secret_access_key = credentials.fetch(:secret_access_key)
      self.access_key_id     = credentials.fetch(:access_key_id)
    end

    def params
      @params ||= {}
    end

    def get(params = {})
      self.params = params
      handle_response(request).body.force_encoding(Encoding::UTF_8)
    end

    def handle_response(response)
      case response.status.to_i
      when 200...300
        response
      when 300...600
        if response.body.nil?
          raise ResponseError.new(nil, response)
        else
          xml = MultiXml.parse(response.body)
          message = xml["Response"]["Errors"]["Error"]["Message"]
          raise ResponseError.new(message, response)
        end
      else
        raise ResponseError.new("Unknown code: #{response.code}", response)
      end
    end

    def request
      conn = Faraday.new url: uri
      conn.get do |req|
        req.headers["Accept"] = "application/xml"
        req.headers["Content-Type"] = "application/xml"
        req.headers["x-amz-date"] = timestamp
        req.headers["Authorization"] = authorization_header
      end
    end

    def timestamp
      @timestamp ||= ( Time::now ).utc.strftime("%Y%m%dT%H%M%SZ")
    end

    def datestamp
      @datestamp ||= ( Time::now ).utc.strftime("%Y%m%d")
    end

    def signature
      signing_key = getSignatureKey(secret_access_key, datestamp, SERVICE_REGION, SERVICE_NAME)
      signature = OpenSSL::HMAC.hexdigest('sha256', signing_key, string_to_sign)
    end

    def uri
      "https://" + SERVICE_HOST + SERVICE_URI + "?" + query
    end

    def default_params
      {
        "AWSAccessKeyId"   => access_key_id,
        "SignatureMethod"  => "HmacSHA256",
        "SignatureVersion" => "2",
        "Timestamp"        => timestamp,
        "Version"          => Alexa::API_VERSION
      }
    end

    def sign
      "GET\n" + Alexa::API_HOST + "\n/\n" + query
    end

    def query
      default_params.merge(params).map do |key, value|
        "#{key}=#{URI.escape(value.to_s, Regexp.new("[^#{RFC_3986_UNRESERVED_CHARS}]"))}"
      end.sort.join("&")
    end

    def algorithm
      "AWS4-HMAC-SHA256"
    end

    def payload_hash
      Digest::SHA256.hexdigest ""
    end

    def credential_scope
      datestamp + "/" + SERVICE_REGION + "/" + SERVICE_NAME + "/" + "aws4_request"
    end

    def canonical_request
      "GET" + "\n" + SERVICE_URI + "\n" + query + "\n" + headers_str + "\n" + headers_lst + "\n" + payload_hash
    end

    def authorization_header
      algorithm + " " + "Credential=" + access_key_id + "/" + credential_scope + ", " +  "SignedHeaders=" + headers_lst + ", " + "Signature=" + signature
    end

    def string_to_sign
      algorithm + "\n" +  timestamp + "\n" +  credential_scope + "\n" + (Digest::SHA256.hexdigest canonical_request)
    end

    def headers
      {
        "host"        => SERVICE_ENDPOINT,
        "x-amz-date"  => timestamp
      }
    end

    def headers_str
      headers.sort.map{|k,v| k + ":" + v}.join("\n") + "\n"
    end

    def headers_lst
      headers_lst = headers.sort.map{|k,v| k}.join(";")
    end

    ## From AWS documentation
    #

    def getSignatureKey(key, dateStamp, regionName, serviceName)
      kDate    = OpenSSL::HMAC.digest('sha256', "AWS4" + key, dateStamp)
      kRegion  = OpenSSL::HMAC.digest('sha256', kDate, regionName)
      kService = OpenSSL::HMAC.digest('sha256', kRegion, serviceName)
      kSigning = OpenSSL::HMAC.digest('sha256', kService, "aws4_request")
      kSigning
    end

    # escape str to RFC 3986
    def escapeRFC3986(str)
      return URI.escape(str,/[^A-Za-z0-9\-_.~]/)
    end


  end
end
