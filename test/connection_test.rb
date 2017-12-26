require "helper"

describe Alexa::Connection do
  it "calculates signature" do
    connection = Alexa::Connection.new(:access_key_id => "fake", :secret_access_key => "fake")
    connection.stubs(:timestamp).returns("2012-08-08T20:58:32.000Z")

    assert_match /f619b6d949521588c3868e641030ea817f539c128f5139f364436fef163745ec/, connection.signature
  end

  it "normalizes non string params value" do
    connection = Alexa::Connection.new(:access_key_id => "fake", :secret_access_key => "fake")
    connection.stubs(:timestamp).returns("2012-08-08T20:58:32.000Z")
    connection.params = {:custom_value => 3}

    expected = "AWSAccessKeyId=fake&SignatureMethod=HmacSHA256&SignatureVersion=2&Timestamp=2012-08-08T20%3A58%3A32.000Z&Version=2005-07-11&custom_value=3"
    assert_equal expected, connection.query
  end

  it "encodes space character" do
    connection = Alexa::Connection.new(:access_key_id => "fake", :secret_access_key => "fake")
    connection.stubs(:timestamp).returns("2012-08-08T20:58:32.000Z")
    connection.params = {:custom_value => "two beers"}

    expected = "AWSAccessKeyId=fake&SignatureMethod=HmacSHA256&SignatureVersion=2&Timestamp=2012-08-08T20%3A58%3A32.000Z&Version=2005-07-11&custom_value=two%20beers"
    assert_equal expected, connection.query
  end

  it "raises error when unathorized" do
    stub_request(:get, %r{https://awis.amazonaws.com/api.*})
                .with(headers: {'Accept'=>'application/xml', 'Accept-Encoding'=>'gzip;q=1.0,deflate;q=0.6,identity;q=0.3', 'User-Agent'=>%r{.*}, Authorization: %r{.*}, 'Content-Type': %r{.*}, 'X-Amz-Date': %r{.*}})
                .to_return(fixture("unathorized.txt"))
    connection = Alexa::Connection.new(:access_key_id => "wrong", :secret_access_key => "wrong")

    assert_raises Alexa::ResponseError do
      connection.get
    end
  end

  it "raises error when forbidden" do
    stub_request(:get, %r{https://awis.amazonaws.com/api.*})
                .with(headers: {'Accept'=>'application/xml', 'Accept-Encoding'=>'gzip;q=1.0,deflate;q=0.6,identity;q=0.3', 'User-Agent'=>%r{.*}, Authorization: %r{.*}, 'Content-Type': %r{.*}, 'X-Amz-Date': %r{.*}})
                .to_return(fixture("forbidden.txt"))
    connection = Alexa::Connection.new(:access_key_id => "wrong", :secret_access_key => "wrong")

    assert_raises Alexa::ResponseError do
      connection.get
    end
  end
end
