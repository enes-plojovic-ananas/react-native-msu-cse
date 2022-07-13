import { NativeModules, Platform } from 'react-native';

const LINKING_ERROR =
  `The package 'react-native-msu-cse' doesn't seem to be linked. Make sure: \n\n` +
  Platform.select({ ios: "- You have run 'pod install'\n", default: '' }) +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo managed workflow\n';

const MsuCse = NativeModules.MsuCse
  ? NativeModules.MsuCse
  : new Proxy(
      {},
      {
        get() {
          throw new Error(LINKING_ERROR);
        },
      }
    );

export function multiply(a: number, b: number): Promise<number> {
  return MsuCse.multiply(a, b);
}

export function isValidCVV(cvv: string, pan?: string): Promise<boolean> {
  return MsuCse.isValidCVV(cvv, pan);
}

export function detectBrand(pan: string): Promise<string> {
  return MsuCse.detectBrand(pan);
}

export function isValidPan(pan: string): Promise<boolean> {
  return MsuCse.isValidPan(pan);
}

export function isValidExpiry(month: number, year: number): Promise<boolean> {
  return MsuCse.isValidExpiry(month, year);
}

export function encrypt(
  pan: string,
  name: string,
  year: number,
  month: number,
  cvv: string,
  nonce: string
): Promise<string> {
  return MsuCse.encrypt(pan, name, year, month, cvv, nonce);
}
