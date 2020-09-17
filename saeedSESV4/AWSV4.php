<?php

class AWSV4 {

    const SERVICE = 'email';
    const DOMAIN = 'amazonaws.com';

    private $accessKeyID     = null;
    private $secretAccessKey = null;
    private $regionName      = null;
    private $serviceName     = null;
    private $httpMethodName  = null;
    private $canonicalURI    = "/";
    private $queryParametes  = array();
    private $awsHeaders      = array();
    private $payload         = "";

    /* Other variables */
    private $HMACAlgorithm   = "AWS4-HMAC-SHA256";
    private $aws4Request     = "aws4_request";
    private $strSignedHeader = null;
    private $xAmzDate        = null;
    private $currentDate     = null;

    public function __construct($accessKey = null, $secretKey = null, $regionName = 'us-west-2') {
        // $CI = & get_instance();
        // $this->accessKeyID = $CI->config->item('SES_ACCESS_KEY');
        // $this->secretAccessKey = $CI->config->item('SES_SECRET_KEY');
        // $this->regionName = 'us-west-2';  //email.us-west-2.amazonaws.com
        $this->accessKeyID = $accessKey;
        $this->secretAccessKey = $secretKey;
        $this->regionName = $regionName;  //email.us-west-2.amazonaws.com
        $this->serviceName = 'email';
        $this->httpMethodName = 'POST';
        $this->canonicalURI = '/';
        $this->queryParametes = $this->queryParametes;
        $this->awsHeaders = $this->awsHeaders;
        $this->payload = $this->payload;
        $this->content_type = 'application/x-www-form-urlencoded';

        /* Get current timestamp value.(UTC) */
        $this->xAmzDate = $this->getTimeStamp();
        $this->currentDate = $this->getDate();


        $this->_host = self::SERVICE . '.' . $this->regionName . '.' . self::DOMAIN;
        $this->_endpoint = 'https://' . self::SERVICE . '.' . $this->regionName . '.' . self::DOMAIN;

    }

    /**
     * Task 1: Create a Canonical Request for Signature Version 4.
     *
     * @return
     */
    private function prepareCanonicalRequest() {
        $canonicalURL = "";

        /* Step 1.1 Start with the HTTP request method (GET, PUT, POST, etc.), followed by a newline character. */
        $canonicalURL .= $this->httpMethodName . "\n";

        /* Step 1.2 Add the canonical URI parameter, followed by a newline character. */
        $canonicalURL .= $this->canonicalURI . "\n";

        /* Step 1.3 Add the canonical query string, followed by a newline character. */
        $canonicalURL .= http_build_query($this->queryParametes) . "\n";

        /* Step 1.4 Add the canonical headers, followed by a newline character. */
        $signedHeaders = '';
        foreach ($this->awsHeaders as $key => $value) {
            $signedHeaders .= $key . ";";
            $canonicalURL .= $key . ":" . $value . "\n";
        }

        $canonicalURL .= "\n";

        /* Step 1.5 Add the signed headers, followed by a newline character. */
        $this->strSignedHeader = substr($signedHeaders, 0, -1);
        $canonicalURL .=  $this->strSignedHeader . "\n";

        /* Step 1.6 Use a hash (digest) function like SHA256 to create a hashed value from the payload in the body of the HTTP or HTTPS. */
        $canonicalURL .= $this->generateHex($this->payload);

        return $canonicalURL;
    }

    /**
     * Task 2: Create a String to Sign for Signature Version 4.
     *
     * @param canonicalURL
     * @return
     */
    private function prepareStringToSign($canonicalURL) {
        $stringToSign = '';

        /* Step 2.1 Start with the algorithm designation, followed by a newline character. */
        $stringToSign .= $this->HMACAlgorithm . "\n";

        /* Step 2.2 Append the request date value, followed by a newline character. */
        $stringToSign .= $this->xAmzDate . "\n";

        /* Step 2.3 Append the credential scope value, followed by a newline character. */
        $stringToSign .= $this->currentDate . "/" . $this->regionName . "/" . $this->serviceName . "/" . $this->aws4Request . "\n";

        /* Step 2.4 Append the hash of the canonical request that you created in Task 1: Create a Canonical Request for Signature Version 4. */
        $stringToSign .= $this->generateHex($canonicalURL);

        return $stringToSign;
    }

    /**
     * Task 3: Calculate the AWS Signature Version 4.
     *
     * @param stringToSign
     * @return
     */
    private function calculateSignature($stringToSign) {
        /* Step 3.1 Derive your signing key */
        $signatureKey = $this->getSignatureKey($this->secretAccessKey, $this->currentDate, $this->regionName, $this->serviceName);

        /* Step 3.2 Calculate the signature. */
        $signature = hash_hmac("sha256", $stringToSign, $signatureKey, true);

        /* Step 3.2.1 Encode signature (byte[]) to Hex */
        $strHexSignature = strtolower(bin2hex($signature));

        return $strHexSignature;
    }

    /**
     * Task 4: Add the Signing Information to the Request. We'll return Map of
     * all headers put this headers in your request.
     *
     * @return
     */
    public function getHeaders() {
        $this->awsHeaders['content-type'] = $this->content_type;
        $this->awsHeaders['host'] = $this->_host;
        $this->awsHeaders['x-amz-date'] = $this->xAmzDate;

        /* Execute Task 1: Create a Canonical Request for Signature Version 4. */
        $canonicalURL = $this->prepareCanonicalRequest();
        // echo "<br>canonicalURL = ". $canonicalURL;
        /* Execute Task 2: Create a String to Sign for Signature Version 4. */
        $stringToSign = $this->prepareStringToSign($canonicalURL);
        // echo "<br><br>stringToSign = ". $stringToSign;
        /* Execute Task 3: Calculate the AWS Signature Version 4. */
        $signature = $this->calculateSignature($stringToSign);
        // echo "<br><br>signature = ". $signature;
        if ($signature) {
            $header =  array(
                'Content-Type' => $this->content_type,
                'Authorization' => $this->buildAuthorizationString($signature),
                'x-amz-date' => $this->xAmzDate,
            );
            return $header;
        }
    }


    public function sendEmail($envelope)
    {
        $validate = $envelope->validate();
        if (is_object($validate)) {
            return $validate;
        }
        $parameters = $envelope->buildParameters();
        $parameters['Action'] = $envelope->action;
        ksort($parameters);
        $query_parameters = '';
        $canonical_headers = '';
        $signed_headers = '';
        $this->payload = http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
        $header = $this->getHeaders();
        $client = new GuzzleHttp\Client(); 
        $query = [
            'headers' => $header,
            'http_errors' => false
        ];

        $body = $this->payload;
        if (strlen($body)) {
            $query['body'] = $body;
        }
        try {
            $res =  $client->request(
                $this->httpMethodName,
                $this->_endpoint,
                $query
            );
            $result =  array(
                'code' => $res->getStatusCode(),
                'body' => new SimpleXMLElement($res->getBody())
            );
        } catch (Exception $e) {
            echo 'Caught exception: ',  $e->getMessage(), "\n";
        }
    }
    /**
     * Build string for Authorization header.
     *
     * @param strSignature
     * @return
     */
    private function buildAuthorizationString($strSignature) {
        return $this->HMACAlgorithm . " "
                . "Credential=" . $this->accessKeyID . "/" . $this->getDate() . "/" . $this->regionName . "/" . $this->serviceName . "/" . $this->aws4Request . ", "
                . "SignedHeaders=" . $this->strSignedHeader . ", "
                . "Signature=" . $strSignature;
    }

    /**
     * Generate Hex code of String.
     *
     * @param data
     * @return
     */
    private function generateHex($data) {
        return strtolower(bin2hex(hash("sha256", $data, true)));
    }

    /**
     * Generate AWS signature key.
     *
     * @param key
     * @param date
     * @param regionName
     * @param serviceName
     * @return
     * @throws Exception
     * @referenceGuzzleHttp\
     * http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-java
     */
    private function getSignatureKey($key, $date, $regionName, $serviceName) {
        $kSecret = "AWS4" . $key;
        $kDate = hash_hmac("sha256", $date, $kSecret, true);
        $kRegion = hash_hmac("sha256", $regionName, $kDate, true);
        $kService = hash_hmac("sha256", $serviceName, $kRegion, true);
        $kSigning = hash_hmac("sha256", $this->aws4Request, $kService, true);

        return $kSigning;
    }

    /**
     * Get timestamp. yyyyMMdd'T'HHmmss'Z'
     *
     * @return
     */
    private function getTimeStamp() {
        return gmdate("Ymd\THis\Z");
    }

    /**
     * Get date. yyyyMMdd
     *
     * @return
     */
    private function getDate() {
        return gmdate("Ymd");
    }
}