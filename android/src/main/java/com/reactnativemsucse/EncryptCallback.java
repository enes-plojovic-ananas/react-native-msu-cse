package com.reactnativemsucse;

/**
 * Created by jasmin.suljic@monri.com
 * MSU CSE
 */
public interface EncryptCallback {
  void onSuccess(String result);

  void onError(EncryptException encryptException);
}
