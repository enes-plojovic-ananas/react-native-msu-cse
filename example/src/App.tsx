import * as React from 'react';

import { StyleSheet, View, Text } from 'react-native';
import {
  encrypt,
  detectBrand,
  isValidCVV,
  isValidExpiry,
  isValidPan,
  multiply,
} from 'react-native-msu-cse';

export default function App() {
  const [result, setResult] = React.useState<string | boolean | undefined>();

  React.useEffect(() => {
    encrypt('4556085311687546', 'Enes Plojovic', 29, 9, '190', 'nonce').then(
      setResult
    );
    // detectBrand('348367846999807').then(setResult);
    // detectBrand('4556085311687546').then(setResult);
    // multiply(2, 5).then(setResult);
    // isValidExpiry(2, 23).then(setResult);
    // isValidCVV('131', '4556085311687546').then(setResult);
    // isValidPan('4556085311687546').then(setResult);
  }, []);

  return (
    <View style={styles.container}>
      <Text>Result: {result?.toString()}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  box: {
    width: 60,
    height: 60,
    marginVertical: 20,
  },
});
