require 'rest-client'
require 'net/http'
require 'digest'
require 'base64'
require 'openssl'

RSpec::Matchers.define :be_a_multiple_of do |expected|
  match do |actual|
    actual % expected == 0
  end
end

RSpec::Matchers.define :respond_with do |expected|
  match do |actual|
    actual.is_a?(expected)
  end
end

describe 'nginx mod' do
  before :all do
    nginx_dir = Dir['nginx-*'][0]
    @nginx_pid = spawn "#{nginx_dir}/prefix/sbin/nginx"
    sleep 1
  end

  after :all do
    Process.kill "TERM", @nginx_pid
  end

  describe 'access key' do
    it 'should disallow access to content without an access key' do
      expect {RestClient.get 'http://localhost:8080/download/stuff.html'}.to raise_error(RestClient::Forbidden)
    end
    
    it 'should allow access to content with an access key' do
      response = RestClient.get "http://localhost:8080/download/stuff.html?key=#{Digest::MD5.hexdigest("mypass")}"
      response.code.should == 200
    end
  end

  describe 'G2O headers' do
    before :each do
      @uri = URI.parse('http://localhost:8080/download/stuff.html')
    end

    it 'should allow access to content with correct G2O headers' do
      time = Time.now.to_i
      data = "3, 69.31.17.132, 80.169.32.154, #{time}, 13459971.1599924223, 117542"
      sign = sign_data(data)
      
      get(data, sign).should respond_with(Net::HTTPOK)
    end

    it 'should disallow access to content with time more than 30 seconds into the future' do
      time = Time.now.to_i
      data = "3, 69.31.17.132, 80.169.32.154, #{time + 31}, 13459971.1599924223, 117542"
      sign = sign_data(data)
      
      get(data, sign).should respond_with(Net::HTTPForbidden)
    end
    
    it 'should disallow access to content with wrong signature' do
      data = '3, 69.31.17.132, 80.169.32.154, 1311262737, 13459971.1599924223, 117542'
      sign = "wrong sig"
      
      get(data, sign).should respond_with(Net::HTTPForbidden)
    end
    
    it 'should disallow access to content without G2O headers' do
      get.should respond_with(Net::HTTPForbidden)
    end

    def get(data = nil, sign = nil)
      Net::HTTP.start(@uri.host, @uri.port) do |http|
        headers = {}

        headers["X-Akamai-G2O-Auth-Data"] = data if data
        headers["X-Akamai-G2O-Auth-Sign"] = sign if sign

        http.get(@uri.path, headers)
      end
    end
    
    def sign_data(data)
      key = 'a_password'
      digest = OpenSSL::HMAC.digest('md5', key, data + @uri.path)
      Base64.encode64(digest)
    end
  end
end
