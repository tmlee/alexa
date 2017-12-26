require "helper"

describe Alexa::API::CategoryListings do
  it "raises argument error when path not present" do
    assert_raises Alexa::ArgumentError, /path/ do
      Alexa::API::CategoryListings.new(:access_key_id => "fake", :secret_access_key => "fake").fetch
    end
  end

  describe "parsing xml" do
    before do
      stub_request(:get, %r{https://awis.amazonaws.com/api.*})
                .with(headers: {'Accept'=>'application/xml', 'Accept-Encoding'=>'gzip;q=1.0,deflate;q=0.6,identity;q=0.3', 'User-Agent'=>%r{.*}, Authorization: %r{.*}, 'Content-Type': %r{.*}, 'X-Amz-Date': %r{.*}})
                .to_return(fixture("category_listings/card_games.txt"))
      @category_listings = Alexa::API::CategoryListings.new(:access_key_id => "fake", :secret_access_key => "fake")
      @category_listings.fetch(:path => "Top/Games/Card_Games")
    end

    it "returns recursive count" do
      assert_equal 1051, @category_listings.recursive_count
    end

    it "returns count" do
      assert_equal 1, @category_listings.count
    end

    it "returns listings" do
      assert_equal 20, @category_listings.listings.size
    end

    it "has success status code" do
      assert_equal "Success", @category_listings.status_code
    end

    it "has request id" do
      assert_equal "a069b6cd-309f-df52-88be-1bd88ab45b7e", @category_listings.request_id
    end
  end
end
