//
//  SoundController.m
//  BonjourChat
//
//  Created by volodymyrkhmil on 11/24/16.
//  Copyright © 2016 Oliver Drobnik. All rights reserved.
//

#import "SoundController.h"
#import "BonjourChatServer.h"
#import "BonjourChatClient.h"
#import "DTBonjourDataConnection.h"
#import "BBBAudioChunkPlayer.h"

#define kOutputBus 0
#define kInputBus 1

// ...

@interface SoundController () <DTBonjourDataConnectionDelegate, DTBonjourServerDelegate, AVCaptureAudioDataOutputSampleBufferDelegate, BBBAudioStream>
@property (nonatomic, strong) AVCaptureSession *session;
@property (nonatomic, strong) NSMutableArray *data;

@end

@implementation SoundController
{
    BonjourChatServer *_server;
    BonjourChatClient *_client;
}

@synthesize audioRecorder;
@synthesize recordButton,sendButton,stopButton;
@synthesize stoped;
@synthesize player;

- (nullable NSData*)nextChunk {
    NSData *data = nil;
    if (self.data.count > 0) {
        data = self.data.firstObject;
        [self.data removeObjectAtIndex:0];
    }
    return data;
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Release any cached data, images, etc that aren't in use.
}

#pragma mark - View lifecycle

static dispatch_queue_t processingQueue;

- (void)viewDidLoad
{
    processingQueue = dispatch_queue_create("processingQueue",
                                            DISPATCH_QUEUE_SERIAL);
    self.data = [NSMutableArray new];
    [super viewDidLoad];
    [self startSession];
}

- (void)startSession {
    
    self.session = [AVCaptureSession new];
    
    [self setupInputsForSession:self.session];
    [self setupOutputsForSession:self.session];
}

- (void)setupInputsForSession:(AVCaptureSession *)session {
    AVCaptureInput *audioInput = [self audioInput];
    
    if ([session canAddInput:audioInput]) {
        [session addInput:audioInput];
    }
}

- (AVCaptureInput *)audioInput {
    
    AVCaptureDevice *micDevice = [AVCaptureDevice defaultDeviceWithMediaType:AVMediaTypeAudio];
    
    AVCaptureDeviceInput *micDeviceInput = [[AVCaptureDeviceInput alloc] initWithDevice:micDevice error:nil];
    
    return micDeviceInput;
}

- (void)setupOutputsForSession:(AVCaptureSession *)session {
    
    dispatch_queue_t queue = dispatch_queue_create("com.recordingtest", DISPATCH_QUEUE_SERIAL);
    
    AVCaptureOutput *audioOutput = [self audioOutputForQueue:queue];
    
    if ([session canAddOutput:audioOutput]) {
        
        [session addOutput:audioOutput];
    }
}

- (AVCaptureOutput *)audioOutputForQueue:(dispatch_queue_t)queue {
    
    AVCaptureAudioDataOutput *audioOutput = [AVCaptureAudioDataOutput new];
    
    [audioOutput setSampleBufferDelegate:self queue:queue];
    
    return audioOutput;
}

#pragma mark - AVCaptureDataOutputSampleBufferDelegate

- (void)captureOutput:(AVCaptureOutput *)captureOutput didOutputSampleBuffer:(CMSampleBufferRef)sampleBuffer fromConnection:(AVCaptureConnection *)connection {
    
    CMSampleBufferRef m_sampleBuffer;
    OSStatus status = CMSampleBufferCreateCopy(kCFAllocatorDefault, sampleBuffer, &m_sampleBuffer);
    dispatch_async(processingQueue, ^{
        if (m_sampleBuffer == NULL) {
            //        m_sampleBuffer = nil;
            return;
        }
        AudioBufferList audioBufferList;
        NSMutableData *data=[[NSMutableData alloc] init];
        CMBlockBufferRef blockBuffer;
        CMSampleBufferGetAudioBufferListWithRetainedBlockBuffer(m_sampleBuffer, NULL, &audioBufferList, sizeof(audioBufferList), NULL, NULL, 0, &blockBuffer);
        CFRelease(m_sampleBuffer);
        CFRelease(blockBuffer);
        for( int y=0; y<audioBufferList.mNumberBuffers; y++ )
        {
            AudioBuffer audioBuffer = audioBufferList.mBuffers[y];
            Float32 *frame = (Float32*)audioBuffer.mData;
            
            
            [data appendBytes:frame length:audioBuffer.mDataByteSize];
        }
        [self sendAudioToServer:data];
    });
}

- (void)prepareOutput {
    [[BBBAudioChunkPlayer sharedPlayer] setPlay:YES];
    [[BBBAudioChunkPlayer sharedPlayer] prepareWithStream:self];
}

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
    
    if ([self.chatRoom isKindOfClass:[BonjourChatServer class]])
    {
        _server = self.chatRoom;
        _server.delegate = self;
        self.navigationItem.title = _server.roomName;
    }
    else if ([self.chatRoom isKindOfClass:[NSNetService class]])
    {
        NSNetService *service = self.chatRoom;
        
        _client = [[BonjourChatClient alloc] initWithService:service];
        _client.delegate = self;
        [_client open];
        
        self.navigationItem.title = _client.roomName;
    }
    
    [self prepareOutput];
}

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation
{
    // Return YES for supported orientations
    return (interfaceOrientation != UIInterfaceOrientationPortraitUpsideDown);
}

- (void) sendAudioToServer :(NSData *)data {
    NSData *d = [NSData dataWithData:data];
    if (_server)
    {
        [_server broadcastObject:d];
    }
    else if (_client)
    {
        NSError *error;
        if (![_client sendObject:d error:&error])
        {
            UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"Error" message:[error localizedDescription] delegate:nil cancelButtonTitle:@"Ok" otherButtonTitles:nil];
            [alert show];
        }
    }
}

- (IBAction)startRec:(id)sender {
    [self.session startRunning];
}

- (IBAction)sendToServer:(id)sender {
    
}

- (IBAction)stop:(id)sender {
    [[BBBAudioChunkPlayer sharedPlayer] stop];
}
- (IBAction)playlastPressed:(id)sender {
    [[BBBAudioChunkPlayer sharedPlayer] start];
}

- (void)playSoundfromData:(NSData*)data {
}

#pragma mark - DTBonjourServer Delegate (Server)

- (void)bonjourServer:(DTBonjourServer *)server didReceiveObject:(id)object onConnection:(DTBonjourDataConnection *)connection
{
    [self.data addObject:object];
}

#pragma mark - DTBonjourConnection Delegate (Client)

- (void)connection:(DTBonjourDataConnection *)connection didReceiveObject:(id)object
{
    [self.data addObject:object];
}

- (void)connectionDidClose:(DTBonjourDataConnection *)connection
{
    if (connection == _client)
    {
        UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"Room Closed" message:@"The Server has closed the room." delegate:self cancelButtonTitle:@"Exit" otherButtonTitles:nil];
        [alert show];
    }
}

- (void)alertView:(UIAlertView *)alertView clickedButtonAtIndex:(NSInteger)buttonIndex
{
    [self.navigationController popViewControllerAnimated:YES];
}

@end
