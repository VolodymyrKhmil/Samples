//
//  SoundController.h
//  BonjourChat
//
//  Created by volodymyrkhmil on 11/24/16.
//  Copyright © 2016 Oliver Drobnik. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <AVFoundation/AVFoundation.h>

@interface SoundController : UIViewController <AVAudioRecorderDelegate>

@property (nonatomic, retain) AVAudioRecorder *audioRecorder;
@property (nonatomic, strong) AVAudioPlayer *player;
@property (nonatomic, retain) IBOutlet UIButton *recordButton;
@property (nonatomic, retain) IBOutlet UIButton *stopButton;
@property (nonatomic, retain) IBOutlet UIButton *sendButton;

@property BOOL stoped;
@property (nonatomic, strong) id chatRoom;

@property(nonatomic,strong) AVAudioRecorder *recorder;
@property(nonatomic,strong) NSMutableDictionary *recorderSettings;
@property(nonatomic,strong) NSString *recorderFilePath;
@property(nonatomic,strong) AVAudioPlayer *audioPlayer;
@property(nonatomic,strong) NSString *audioFileName;

- (IBAction)startRecording:(id)sender;
- (IBAction)stopRecording:(id)sender;

- (IBAction)startPlaying:(id)sender;
- (IBAction)stopPlaying:(id)sender;


- (IBAction)sendToServer:(id)sender;
@end
