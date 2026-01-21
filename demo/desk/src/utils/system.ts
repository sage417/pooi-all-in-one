import si from 'systeminformation';
import crypto from 'crypto';

const virtualMacPrefixes = [
  '00:05:69', '00:0c:29', '00:1c:14', '00:50:56', // VMware
  '00:03:ff', '00:15:5d', // Microsoft Hyper-V
  '08:00:27', '0a:00:27'  // VirtualBox
];

const virtualNamePatterns = [
  'virtual', 'vmware', 'hyper-v', 'virtualbox',
  'virbr', 'veth', 'docker', 'tap', 'wsl'
];

const computeDeviceFingerprint = async (): Promise<string> => {
  // Get CPU information
  const cpuInfo = await si.cpu();
  const cpuId = `${cpuInfo.manufacturer}-${cpuInfo.brand}-${cpuInfo.model}`;

  // Get network interface information
  let networkInterfaces = await si.networkInterfaces();
  networkInterfaces = Array.isArray(networkInterfaces) ? networkInterfaces : [networkInterfaces];

  const macAddresses = networkInterfaces
    .filter((item) => isPhysicalInterface(item))
    .map((item) => item.mac?.trim())
    .filter((mac, index, self) => self.indexOf(mac) === index)
    .sort();
    
  return crypto.createHash('sha256').update(`${cpuId}-${macAddresses}`).digest('hex')
}

const isPhysicalInterface = (item: si.Systeminformation.NetworkInterfacesData): boolean => {
  // Exclude invalid MAC addresses
  if (!item.mac || item.mac === '00:00:00:00:00:00') {
    return false;
  }

  // Check known virtual network card OUI prefixes
  const mac = item.mac.toLowerCase();
  if (virtualMacPrefixes.some(prefix => mac.startsWith(prefix))) {
    return false;
  }

  // Check interface names
  const iface = item.iface?.toLowerCase() || '';

  if (virtualNamePatterns.some(pattern => iface.includes(pattern))) {
    return false;
  }

  return true;
};

export {
  computeDeviceFingerprint
}