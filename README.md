# pyiatrebuild
Use this library to automatically rebuild the import address table for a PE dumped from memory. It also be used to fully dump and rebuild a PE from memory.


**WARNING!** I only wrote this because I couldn't find an existing tool with python bindings. 
This is _not_ a replacement for ImpREC. ImpREC will always be a better choice because it's awesome and eats malware for breakfast while shooting lasers out of it's eyes!! ImpREC and malware analysts form like Voltron! 

![](http://reactiongifs.me/wp-content/uploads/2013/12/Christmas-reindeer-transformer-santa-claus-warrior-psychedelic-reindeer.gif)

Only use this inferior tool if you need to do some automated reconstruction via python.

## Caveats 
* This library can only be run on Windows (obviously).
* This library must be run on the host where the PE is being dumped and the process that the PE was dumped from **must still be active**. The setup is the same as the famous ImpREC tool. 
* You must provide the OEP (virtual address not RVA), and the module base address. You should already have these from the unpacking process that dumped the file in the first place.
* You must pass the the PE file that is to be rebuilt as a binary string. The PE file must be in its unmapped format with a PE header that will **at least provide correct section information**. All other information can be incorrect and will be fixed by the library.
* Currently pyiatrebuild does not handle relocation. The output PE will be marked as not relocatable. 

## Installation 
pyiatrebuild requires the following modules to be installed:
* winappdbg
* elfesteem
* distorm3

Once these are installed you simply need to clone this repository and use as you see fit!

### winappdbg
Winappdb can be installed via pip.

### elfesteem
**Do not** install the version of elfesteem available via pip. This version is old and won't work with our library. Instead, clone the repository [https://github.com/serpilliere/elfesteem](https://github.com/serpilliere/elfesteem) and install from there.

### distorm3
Though distorm3 pretends that it can be installed via pip we all know it's going to fail for some reason. Just save yourself the headache and download the installer from [https://pypi.python.org/pypi/distorm3](https://pypi.python.org/pypi/distorm3) and install it that way.

## Usage
This is really meant to be used as a library but there is a small cli example included.
*Rebuild the IAT for a dumped file (already saved to disk with valid PE header).*
 
`python pyiatrebuild.py rebuild --pid 3368 --base_address 589824 --oep 598738 dumped.bin out.exe`

*Dump PE from process, fix header, and rebuild IAT.*
 
`python pyiatrebuild.py rebuild dump --pid 3368 --oep 598738 out.exe`

### ProTip
If you don't need to rebuild a full PE and just want to resolve some pointers to import into IDA you can pass a list of pointers and the PID to pyiatrebuild.reslove_iat_pointers and it will return a dictionary with the module and function names resolved for the pointers you provided. 

## Acknowledgments
* Big thank you to @MarioVilas for the wonder that is winappdbg
* Also, huge thank you to @serpilliere (Fabrice DESCLAUX) and Philippe Biondi for elfesteem
* Lastly, hat tip to @kbandla for the [immunity scripts](https://github.com/kbandla/ImmunityDebuggerScripts) shedding some light on how to do things more efficiently.


## Feedback / Help
* Any questions, comments, requests hit me up on twitter: @herrcore 
* Pull requests welcome!