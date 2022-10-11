package com.reactnativemsucse;

import android.os.AsyncTask;
import android.os.Handler;
import android.os.Looper;
import androidx.annotation.NonNull;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.module.annotations.ReactModule;

import java.util.Calendar;

@ReactModule(name = MsuCseModule.NAME)
public class MsuCseModule extends ReactContextBaseJavaModule {
  public static final String NAME = "MsuCse";
  private AsyncTask<Void, Void, EncryptTaskResult> task;
  private final Handler handler = new Handler(Looper.getMainLooper());

  public MsuCseModule(ReactApplicationContext reactContext) {
    super(reactContext);
  }

  @Override
  @NonNull
  public String getName() {
    return NAME;
  }


  // Example method
  // See https://reactnative.dev/docs/native-modules-android
  @ReactMethod
  public void multiply(double a, double b, Promise promise) {
    promise.resolve(a * b);
  }

  /**
   * @param month
   * @param year
   * @return
   */
  @ReactMethod
  public void isValidExpiry(Integer month, Integer year, Promise promise) {
    promise.resolve(CardUtils.isValidExpiry(Calendar.getInstance(), month, year));
  }

  @ReactMethod
  public void isValidCVV(String cvv, String pan, Promise promise) {
    promise.resolve(CardUtils.isValidCVV(cvv, pan));
  }

  @ReactMethod
  public void isValidPan(String pan, Promise promise) {
    promise.resolve(CardUtils.isValidPan(pan));
  }

  @ReactMethod
  public void detectBrand(String pan, Promise promise) {
    promise.resolve(CardUtils.detectBrand(pan).getBrand());
  }

  @ReactMethod
  public void encrypt(String pan,
                      String cardHolderName,
                      Integer expiryYear,
                      Integer expiryMonth,
                      String cvv,
                      String nonce,
                      Boolean developmentMode,
                      Promise promise) {

    EncryptRequest request = new CardEncryptRequest(pan, expiryYear, expiryMonth, cardHolderName, cvv, nonce);
    EncryptCallback callback = new EncryptCallback() {
      @Override
      public void onSuccess(String result) {
        promise.resolve(result);
      }
      @Override
      public void onError(EncryptException encryptException) {
        promise.resolve("Error: " + encryptException.getCode().toString());
      }
    };

    CSEApi cseApi = new CSEApiImpl(developmentMode);

    try {
      if (request.validate()) {
        this.task = new EncryptTask(callback, request, cseApi).execute();
      } else {
        callback.onError(EncryptException.create(EncryptExceptionCode.VALIDATION_FAILED));
      }
    } catch (final Exception e) {
      handler.post(() -> callback.onError(EncryptException.create(e, EncryptExceptionCode.UNKNOWN_EXCEPTION)));
    }
  }
}
