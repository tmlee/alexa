require "helper"

describe Alexa::API::SitesLinkingIn do
  it "raises argument error when url not present" do
    assert_raises Alexa::ArgumentError, /url/ do
      Alexa::API::SitesLinkingIn.new(:access_key_id => "fake", :secret_access_key => "fake").fetch
    end
  end

  describe "parsing xml" do
    before do
      stub_request(:get, %r{https://awis.amazonaws.com/api.*})
                .with(headers: {'Accept'=>'application/xml', 'Accept-Encoding'=>'gzip;q=1.0,deflate;q=0.6,identity;q=0.3', 'User-Agent'=>%r{.*}, Authorization: %r{.*}, 'Content-Type': %r{.*}, 'X-Amz-Date': %r{.*}})
                .to_return(fixture("sites_linking_in/github_count_3.txt"))
      @sites_linking_in = Alexa::API::SitesLinkingIn.new(:access_key_id => "fake", :secret_access_key => "fake")
      @sites_linking_in.fetch(:url => "github.com", :count => 3)
    end

    it "returns sites" do
      assert_equal 3, @sites_linking_in.sites.size
    end

    it "has Title attribute on single site" do
      assert_equal "google.com", @sites_linking_in.sites.first["Title"]
    end

    it "has Url attribute on single site" do
      assert_equal "code.google.com:80/a/eclipselabs.org/p/m2eclipse-android-integration", @sites_linking_in.sites.first["Url"]
    end

    it "has success status code" do
      assert_equal "Success", @sites_linking_in.status_code
    end

    it "has request id" do
      assert_equal "abb553a3-035f-8d12-f353-40532a087b52", @sites_linking_in.request_id
    end
  end
end
