//
//  ViewController.m
//  CertificatePinning
//
//  Created by Oliver Ng on 30/5/15.
//  Copyright (c) 2015 Security Compass. All rights reserved.
//  http://www.securitycompass.com
//

#import "ViewController.h"

// We extend NSURLConnectionDelegate to access and override willSendRequestForAuthChallenge()

@interface ViewController () <NSURLConnectionDelegate>

- (IBAction)PinnedRequestAction;

@property (weak, nonatomic) IBOutlet UITextField *urlField;
@property (strong, nonatomic) NSURLConnection *connection;
@property (strong, nonatomic) NSMutableData *responseData;

@end



@implementation ViewController

- (void)viewDidLoad {
  [super viewDidLoad];
  // Do any additional setup after loading the view, typically from a nib.
}


// This function is performed once the user clicks on the CONNECT button.
- (IBAction)PinnedRequestAction{

  // get the textfield from the UI and convert to URL
  NSString *url = self.urlField.text;
  NSURL *validUrl = [NSURL URLWithString:url];
  
  // validate the URL
  if ( [url hasPrefix:@"https://"] && (validUrl != nil) ){
    NSURLRequest *request = [NSURLRequest requestWithURL:validUrl
                                             cachePolicy:NSURLRequestReloadIgnoringLocalAndRemoteCacheData
                                         timeoutInterval:15.0f];
  
    // start the connection using this class as the NSURLConnectionDelegate so we can manage connection()
    self.connection = [NSURLConnection connectionWithRequest:request delegate:self];
    [self.connection start];
  }
  else{
    // notify the user that the URL is invalid or not HTTPS
    [self createAlert:@"Specify an https:// URL and the URL must be wellformed."];
  }
}


// This method overrides default handling of "trust" in NSURLConnections
// We can use it to perform additional steps to verify certificate trust
// such as for certificate pinning.
- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
  // Setup the connection configuration values
  SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
  SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, 0);
  NSData *remoteCertificateData = CFBridgingRelease(SecCertificateCopyData(certificate));
  
  // provide our local certificate (SC.cer) as stored in Supporting Files (Bundle)
  NSString *cerPath = [[NSBundle mainBundle] pathForResource:@"SC" ofType:@"cer"];
  NSData *localCertData = [NSData dataWithContentsOfFile:cerPath];
  
  // perform the check to see if the remote certificate matches our local certificate
  if ([remoteCertificateData isEqualToData:localCertData]) {
    NSURLCredential *credential = [NSURLCredential credentialForTrust:serverTrust];
    [[challenge sender] useCredential:credential forAuthenticationChallenge:challenge];

    // notify the user that the connection passed certificate pinning checks
    [self createAlert:@"Pass"];
  }
  else {
    // cancel the request since filed check
    [[challenge sender] cancelAuthenticationChallenge:challenge];

    // connection did NOT pass certificate pinning checks
    [self createAlert:@"Site filed check. Did not present valid certificate for www.securitycompass.com"];
    
  }
}



- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data{
  // implement if you want to see data returned from the connection in NSData
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection{
  // implement if you want to take action once NSURLConnection tasks complete
}

// Helper method to create an alert window
- (void)createAlert:(NSString *)message {
  UIAlertView *alert = [[UIAlertView alloc] initWithTitle:NSLocalizedString(@"Note", nil)
                                                  message:NSLocalizedString(message, nil)
                                                 delegate:nil
                                        cancelButtonTitle:NSLocalizedString(@"OK", nil)
                                        otherButtonTitles:nil];
  [alert show];
}


- (void)didReceiveMemoryWarning {
  [super didReceiveMemoryWarning];
  // Dispose of any resources that can be recreated.
}

@end
