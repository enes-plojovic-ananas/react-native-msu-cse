# react-native-msu-cse

Reac Native implementation of MSU CSE

## Installation

```sh
npm install react-native-msu-cse
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
  'someRandomString' // nonce (random generated string - max length: 16 characters)
);
```

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT

---

Made with [create-react-native-library](https://github.com/callstack/react-native-builder-bob)
