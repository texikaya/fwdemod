# fwdemod
FW decoder using RTL SDR software-defined radio

## Setup

### RTL-SDR Setup

#### Windows

Install [librtlsdr](https://github.com/librtlsdr/librtlsdr/releases) into `C:\Windows\System32`

Make sure you download the 32/64 bit package that matches your Python install.

Python for Windows often (counterintuitively) directs users to the 32bit version by default.

Note: you cannot import the `rtlsdr` Python library when the RTL-SDR device isn't connected to the PC.

#### Ubuntu Linux

```bash
sudo apt update
sudo apt install librtlsdr-dev
```

### fwdemod Application Setup

Install the required packages by executing

`python -m pip install -r requirements.txt`

## Usage 

### grab
```bash
python grab.py -h
```
Will show all the options and arguments that are avliable for the program. grab.py scans the radios and will display the packets it captured. When the program finishes, it will list all the radios that are captured and its parameters.

### Args

```-r``` run time(`default` 112 seconds)

```-t``` sample time(`default` 5, `opts`: 1-8)

```-x``` Rf data rate(`default` 3, `opts: `2/3) 

If an output file specified it will save all the info to the file.

### plot
```bash
python plot.py -h
```
Will display all the options. Plot.py plots a spectrum for the given sample file.


## Notes
- if `grab.py dump` displays nothing make sure that the right type of antenna used. Also a different RF data rate can be used. Run the scan again and specify RF data rate by `-x`
- If Min/Max says `"Min/Max: Lots!!"` try increasing the sample time. It can be specified by `-t`(5 or above recommended) 
- Increasing the run time will help gathering more information about the radios.