# partialJailbreak 



### Usage

- git clone https://github.com/0neday/PhoenixNonce-iOS9-partialJailbreak
- Use xcode to compile and install
- Just for developer to research 
- Just for iOS 9.0 - 9.3.5  64bit

### Decrypt 64bit kernelcache for N71AP iOS 9.3
 	 
 - Find kernelcache keys from [here](https://www.theiphonewiki.com/wiki/Eagle_13E234_(iPhone8,1)) only for n71ap, 
 - Use xerub [img4](https://github.com/xerub/img4tool) to decrypt	 kernelcache.

### Issues
- patchfinder64 don't support iOS <10, so you need to patch patchfinder64 for patch kernel.
- miss some kernel structure offsets to remount root partition as r/w or patch amfid (kppless approach). you need to check xnu version of [apple open source](https://opensource.apple.com/source/xnu/) depend on your iOS version


### License

[MIT](https://github.com/Siguza/PhoenixNonce/blob/master/LICENSE).

Uses code from [kern-utils](https://github.com/Siguza/ios-kern-utils) and [cl0ver](https://github.com/Siguza/cl0ver).

### Credits
Siguza, tihmstar, 0nday and others (see source code for details).
