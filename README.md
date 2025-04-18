# Name
MyWindowsSandbox

## Description
This is MY customization of a windows sandbox

## Run instructions
 * Set the correct HostFolder path, point it to the folder containing sandbox.wsb
 * Customize optionals
 * Run sandbox.wsb

 ### Tailscale (optional)
   * Set the Auth Key on the tailscale-config.txt

 ### Veracrypt (optional)
   * Copy the container/volume file to this folder
   * Copy the keyfile to this folder
   * Define these filename on the wsb-startup.ps1 section
   * Password is asked when mounting
 
 ### Installs (optional)
   * Copy your installables (.exe / .msi) files to the Installs folder
   * Complete the installations on the sandbox