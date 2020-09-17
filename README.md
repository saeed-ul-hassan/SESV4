# SESV4
complete package to AWS ses emails 




require_once(APPPATH . 'libraries/saeedSESV4/autoload.php');


try {
    
    $aws4 = new AWSV4('SES_ACCESS_KEY', 'SES_SECRET_KEY', 'us-west-2');
    $envelope = new SimpleEmailServiceEnvelope(
        'EMAIL FROM',
        'SUBJECT',
        'EMAIL BODY'
    );
    $envelope->addTo('saeed.hassan@purelogics.net');
    $aws4->sendEmail($envelope);
} catch (Exception $e) {
    echo 'Caught exception: ',  $e->getMessage(), "\n";
}

DONE :)
