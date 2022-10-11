# react-native-msu-cse

Reac Native implementation of MSU CSE

## Installation

```sh
npm install react-native-msu-cse
```

or

```sh
yarn add react-native-msu-cse
```
Install pods
```sh
cd ios && pod install
```

## Usage

```js
import { encrypt } from 'react-native-msu-cse';

// ...

const result = await encrypt(
  '4556085311687546', // Card Pan
  'John Doe', // Cardholder Name
  24, // Expiry Year
  9, // Expirty Month
  '192', // CVV/CVC
  'someRandomString', // nonce (random generated string - max length: 16 characters),
  true // Development mode
);
```

## License

MIT

---

Made with [create-react-native-library](https://github.com/callstack/react-native-builder-bob)
