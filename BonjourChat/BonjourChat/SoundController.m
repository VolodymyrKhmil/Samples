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

#define kOutputBus 0
#define kInputBus 1

// ...

@interface SoundController () <DTBonjourDataConnectionDelegate, DTBonjourServerDelegate, AVCaptureAudioDataOutputSampleBufferDelegate>
@property (nonatomic, strong) AVCaptureSession *session;

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

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Release any cached data, images, etc that aren't in use.
}

#pragma mark - View lifecycle

static NSMutableData *gotedData;
static NSInteger properIndex = 0;

static OSStatus playbackCallback(void *inRefCon,
                                 AudioUnitRenderActionFlags *ioActionFlags,
                                 const AudioTimeStamp *inTimeStamp,
                                 UInt32 inBusNumber,
                                 UInt32 inNumberFrames,
                                 AudioBufferList *ioData) {
    
    for (int i = 0 ; i < ioData->mNumberBuffers; i++){
        AudioBuffer buffer = ioData->mBuffers[i];
        unsigned char *frameBuffer = buffer.mData;
        unsigned char *bytePtr = (unsigned char *)[gotedData bytes];
        NSInteger length = [gotedData length];
        for (int j = 0; j < inNumberFrames*2; j++){
            unsigned char byte = 0b0;
            if (properIndex + 1 < length) {
                ++properIndex;
                byte = bytePtr[properIndex];
            }
            frameBuffer[j] = byte;
        }
    }
    return noErr;
}

- (void)viewDidLoad
{
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
    
    if(sampleBuffer==NULL)
        return;
    //copy data to file
    //read next one
    AudioBufferList audioBufferList;
    NSMutableData *data=[[NSMutableData alloc] init];
    CMBlockBufferRef blockBuffer;
    CMSampleBufferGetAudioBufferListWithRetainedBlockBuffer(sampleBuffer, NULL, &audioBufferList, sizeof(audioBufferList), NULL, NULL, 0, &blockBuffer);
    // NSLog(@"%@",blockBuffer);
    
    
    
    for( int y=0; y<audioBufferList.mNumberBuffers; y++ )
    {
        AudioBuffer audioBuffer = audioBufferList.mBuffers[y];
        Float32 *frame = (Float32*)audioBuffer.mData;
        
        
        [data appendBytes:frame length:audioBuffer.mDataByteSize];
    }
    
    [self sendAudioToServer:data];
}

- (void)prepareOutput {
    OSStatus status;
    AudioComponentInstance audioUnit;
    
    // Describe audio component
    AudioComponentDescription desc;
    desc.componentType = kAudioUnitType_Output;
    desc.componentSubType = kAudioUnitSubType_RemoteIO;
    desc.componentFlags = 0;
    desc.componentFlagsMask = 0;
    desc.componentManufacturer = kAudioUnitManufacturer_Apple;
    
    // Get component
    AudioComponent inputComponent = AudioComponentFindNext(NULL, &desc);
    
    // Get audio units
    status = AudioComponentInstanceNew(inputComponent, &audioUnit);
    //    checkStatus(status);
    
    // Enable IO for recording
    UInt32 flag = 1;
    status = AudioUnitSetProperty(audioUnit,
                                  kAudioOutputUnitProperty_EnableIO,
                                  kAudioUnitScope_Input,
                                  kInputBus,
                                  &flag,
                                  sizeof(flag));
    //    checkStatus(status);
    
    // Enable IO for playback
    status = AudioUnitSetProperty(audioUnit,
                                  kAudioOutputUnitProperty_EnableIO,
                                  kAudioUnitScope_Output,
                                  kOutputBus,
                                  &flag,
                                  sizeof(flag));
    //    checkStatus(status);
    
    // Describe format
    AudioStreamBasicDescription audioFormat;
    audioFormat.mSampleRate			= 44100.00;
    audioFormat.mFormatID			= kAudioFormatLinearPCM;
    audioFormat.mFormatFlags		= kAudioFormatFlagIsSignedInteger | kAudioFormatFlagIsPacked;
    audioFormat.mFramesPerPacket	= 1;
    audioFormat.mChannelsPerFrame	= 1;
    audioFormat.mBitsPerChannel		= 16;
    audioFormat.mBytesPerPacket		= 2;
    audioFormat.mBytesPerFrame		= 2;
    
    // Apply format
    status = AudioUnitSetProperty(audioUnit,
                                  kAudioUnitProperty_StreamFormat,
                                  kAudioUnitScope_Output,
                                  kInputBus,
                                  &audioFormat,
                                  sizeof(audioFormat));
    //    checkStatus(status);
    status = AudioUnitSetProperty(audioUnit,
                                  kAudioUnitProperty_StreamFormat,
                                  kAudioUnitScope_Input,
                                  kOutputBus,
                                  &audioFormat,
                                  sizeof(audioFormat));
    //    checkStatus(status);
    
    
    // Set input callback
    AURenderCallbackStruct callbackStruct;
    //    callbackStruct.inputProcRefCon = self;
    //    status = AudioUnitSetProperty(audioUnit,
    //                                  kAudioOutputUnitProperty_SetInputCallback,
    //                                  kAudioUnitScope_Global,
    //                                  kInputBus,
    //                                  &callbackStruct,
    //                                  sizeof(callbackStruct));
    //    checkStatus(status);
    
    // Set output callback
    callbackStruct.inputProc = playbackCallback;
    callbackStruct.inputProcRefCon = (__bridge void * _Nullable)(self);
    status = AudioUnitSetProperty(audioUnit,
                                  kAudioUnitProperty_SetRenderCallback,
                                  kAudioUnitScope_Global,
                                  kOutputBus,
                                  &callbackStruct,
                                  sizeof(callbackStruct));
    //    checkStatus(status);
    
    // Disable buffer allocation for the recorder (optional - do this if we want to pass in our own)
    flag = 0;
    status = AudioUnitSetProperty(audioUnit,
                                  kAudioUnitProperty_ShouldAllocateBuffer,
                                  kAudioUnitScope_Output,
                                  kInputBus,
                                  &flag,
                                  sizeof(flag));
    
    // TODO: Allocate our own buffers if we want
    
    // Initialise
    status = AudioUnitInitialize(audioUnit);
    
    status = AudioOutputUnitStart(audioUnit);
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
    [self.session stopRunning];
}
- (IBAction)playlastPressed:(id)sender {

}

- (void)playSoundfromData:(NSData*)data {
}

#pragma mark - DTBonjourServer Delegate (Server)

- (void)bonjourServer:(DTBonjourServer *)server didReceiveObject:(id)object onConnection:(DTBonjourDataConnection *)connection
{
    [gotedData appendData:object];
}

#pragma mark - DTBonjourConnection Delegate (Client)

- (void)connection:(DTBonjourDataConnection *)connection didReceiveObject:(id)object
{
    [gotedData appendData:object];
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
