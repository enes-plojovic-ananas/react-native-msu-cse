import Foundation
import Security

public enum CardBrand: String {
    case Visa = "visa"
    case Mastercard = "mastercard"
    case Maestro = "maestro"
    case AmericanExpress = "american-express"
    case DinersClub = "diners-club"
    case Discover = "discover"
    case Jcb = "jcb"
    case Troy = "troy"
    case Dinacard = "dinacard"
    case UnionPay = "union-pay"
    case Unknown = "unknown"
}

@available(iOS 10.0, *)
internal class RSAEncryption {
    static func encrypt(_ publicKey: String, plain: String) -> EncryptionResult {
        
        guard let d = plain.data(using: .utf8) else {
            return .error(.encryptionFailed("Unable to transform \(plain) to data"))
        }
        
        do {
            guard let encrypted = try RSAUtils.encryptWithRSAPublicKey(data: d, pubkeyBase64: publicKey, tagName: "") else {
                return .error(.encryptionFailed("Encryption failed"))
            }
            let rv = encrypted.base64EncodedString(options: [])
            return .success(rv)
        } catch {
            return .error(.encryptionFailed(error.localizedDescription))
        }
    }
}

internal enum EncryptionResult {
    case success(String)
    case error(EncryptionError)
}

//
//  RsaUtils.swift
//  SwiftUtils
//
//  Created by Thanh Nguyen on 9/16/16.
//  Copyright © 2016 Thanh Nguyen. All rights reserved.
//----------------------------------------------------------------------
//  RSA utilities.
//  Credits:
//  - https://github.com/ideawu/Objective-C-RSA
//  - http://netsplit.com/swift-storing-key-pairs-in-the-keyring
//  - http://netsplit.com/swift-generating-keys-and-encrypting-and-decrypting-text
//  - http://hg.mozilla.org/services/fx-home/file/tip/Sources/NetworkAndStorage/CryptoUtils.m#l1036
//----------------------------------------------------------------------

@available(iOS 10.0, *)
internal class RSAUtils {

    private static let PADDING_FOR_DECRYPT = SecPadding()

    
    public class RSAUtilsError: NSError {
        init(_ message: String) {
            super.init(domain: "com.github.btnguyen2k.SwiftUtils.RSAUtils", code: 500, userInfo: [
                NSLocalizedDescriptionKey: message
            ])
        }

        @available(*, unavailable)
        required public init?(coder aDecoder: NSCoder) {
            fatalError("init(coder:) has not been implemented")
        }
    }

    // Base64 encode a block of data
    
    private static func base64Encode(_ data: Data) -> String {
        return data.base64EncodedString(options: [])
    }

    // Base64 decode a base64-ed string
    
    private static func base64Decode(_ strBase64: String) -> Data {
        let data = Data(base64Encoded: strBase64, options: [])
        return data!
    }

    /**
     * Deletes an existing RSA key specified by a tag from keychain.
     *
     * - Parameter tagName: tag name to query for RSA key from keychain
     */
    
    public static func deleteRSAKeyFromKeychain(_ tagName: String) {
        let queryFilter: [String: AnyObject] = [
            String(kSecClass)             : kSecClassKey,
            String(kSecAttrKeyType)       : kSecAttrKeyTypeRSA,
            String(kSecAttrApplicationTag): tagName as AnyObject
        ]
        SecItemDelete(queryFilter as CFDictionary)
    }

    /**
     * Gets an existing RSA key specified by a tag from keychain.
     *
     * - Parameter tagName: tag name to query for RSA key from keychain
     *
     * - Returns: SecKey reference to the RSA key
     */
    
    public static func getRSAKeyFromKeychain(_ tagName: String) -> SecKey? {
        let queryFilter: [String: AnyObject] = [
            String(kSecClass)             : kSecClassKey,
            String(kSecAttrKeyType)       : kSecAttrKeyTypeRSA,
            String(kSecAttrApplicationTag): tagName as AnyObject,
            //String(kSecAttrAccessible)    : kSecAttrAccessibleWhenUnlocked,
            String(kSecReturnRef)         : true as AnyObject
        ]

        var keyPtr: AnyObject?
        let result = SecItemCopyMatching(queryFilter as CFDictionary, &keyPtr)
        if ( result != noErr || keyPtr == nil ) {
            return nil
        }
        return keyPtr as! SecKey?
    }

    /**
     * Adds a RSA public key to keychain and returns its SecKey reference.
     *
     * - Parameter pubkeyBase64: X509 public key in base64 (data between "-----BEGIN PUBLIC KEY-----" and "-----END PUBLIC KEY-----")
     * - Parameter tagName: tag name to store RSA key to keychain
     *
     * - Throws: `RSAUtilsError` if the input key is indeed not a X509 public key
     *
     * - Returns: SecKey reference to the RSA public key.
     */
    
    public static func addRSAPublicKey(_ pubkeyBase64: String, tagName: String) throws -> SecKey? {
        let fullRange = NSRange(location: 0, length: pubkeyBase64.lengthOfBytes(using: .utf8))
        let regExp = try! NSRegularExpression(pattern: "(-----BEGIN.*?-----)|(-----END.*?-----)|\\s+", options: [])
        let myPubkeyBase64 = regExp.stringByReplacingMatches(in: pubkeyBase64, options: [], range: fullRange, withTemplate: "")
        return try addRSAPublicKey(base64Decode(myPubkeyBase64), tagName: tagName)
    }

    /**
     * Adds a RSA pubic key to keychain and returns its SecKey reference.
     *
     * - Parameter pubkey: X509 public key
     * - Parameter tagName: tag name to store RSA key to keychain
     *
     * - Throws: `RSAUtilsError` if the input key is not a valid X509 public key
     *
     * - Returns: SecKey reference to the RSA public key.
     */
    
    private static func addRSAPublicKey(_ pubkey: Data, tagName: String) throws -> SecKey? {
        // Delete any old lingering key with the same tag
        deleteRSAKeyFromKeychain(tagName)

        let pubkeyData = pubkey

        // Add persistent version of the key to system keychain
        //var prt1: Unmanaged<AnyObject>?
        let queryFilter: [String : Any] = [
            (kSecClass as String)              : kSecClassKey,
            (kSecAttrKeyType as String)        : kSecAttrKeyTypeRSA,
            (kSecAttrApplicationTag as String) : tagName,
            (kSecValueData as String)          : pubkeyData,
            (kSecAttrKeyClass as String)       : kSecAttrKeyClassPublic,
            (kSecReturnPersistentRef as String): true
            ] as [String : Any]
        let result = SecItemAdd(queryFilter as CFDictionary, nil)
        if ((result != noErr) && (result != errSecDuplicateItem)) {
            return nil
        }

        return getRSAKeyFromKeychain(tagName)
    }
    
    

    /**
     * Encrypts data with a RSA key.
     *
     * - Parameter data: the data to be encrypted
     * - Parameter rsaKeyRef: the RSA key
     * - Parameter padding: padding used for encryption
     *
     * - Returns: the data in encrypted form
     */
    public static func encryptWithRSAKey2(_ data: Data, rsaKeyRef: SecKey, padding: SecPadding) -> Data? {
        let algorithm: SecKeyAlgorithm = .rsaEncryptionOAEPSHA256
        var error: Unmanaged<CFError>?
        guard let cipherText = SecKeyCreateEncryptedData(rsaKeyRef,
                                                         algorithm,
                                                         data as CFData,
                                                         &error) as Data? else {
                                                            return nil
        }
        
        return cipherText
    }

    /*----------------------------------------------------------------------*/

    /**
     * Encrypts data using RSA public key.
     *
     * Note: the public key will be stored in keychain specified by tagName.
     *
     * - Parameter data: data to be encrypted
     * - Parameter pubkeyBase64: X509 public key in base64 (data between "-----BEGIN PUBLIC KEY-----" and "-----END PUBLIC KEY-----")
     * - Parameter tagName: tag name to store RSA key to keychain
     *
     * - Throws: `RSAUtilsError` if the supplied key is not a valid X509 public key
     *
     * - Returns: the data in encrypted form
     */
    
    public static func encryptWithRSAPublicKey(data: Data, pubkeyBase64: String, tagName: String) throws -> Data? {
        let tagName1 = "PUBIC-" + String(pubkeyBase64.hashValue)
        var keyRef = getRSAKeyFromKeychain(tagName1)
        if ( keyRef == nil ) {
            keyRef = try addRSAPublicKey(pubkeyBase64, tagName: tagName1)
        }
        if ( keyRef == nil ) {
            return nil
        }

        return encryptWithRSAKey2(data, rsaKeyRef: keyRef!, padding: SecPadding.OAEP)
    }

}

internal class CardUtils {
    
    static let  LENGTH_COMMON_CARD = 16;
    static let  LENGTH_AMERICAN_EXPRESS = 15;
    static let  LENGTH_DINERS_CLUB = 14;
    static let MAESTRO_CARD_LENGTH = [12, 13, 14, 15, 16, 17, 18, 19]
    static let VISA_CARD_LENGTH = [16, 19]
    
    static let  PREFIXES_AMERICAN_EXPRESS = ["34", "37"]
    static let  PREFIXES_DISCOVER = ["60", "64", "65"]
    static let  PREFIXES_JCB = ["35"];
    static let  PREFIXES_DINERS_CLUB = ["300", "301", "302", "303", "304",
            "305", "309", "36", "38", "39"]
    static let  PREFIXES_VISA = ["4"];
    static let  PREFIXES_MASTERCARD = [
            "2221", "2222", "2223", "2224", "2225", "2226", "2227", "2228", "2229",
            "223", "224", "225", "226", "227", "228", "229",
            "23", "24", "25", "26",
            "270", "271", "2720",
            "50", "51", "52", "53", "54", "55", "67"
    ]
    
    static let  PREFIXES_UNIONPAY = ["62"]
    
    static let PREFIXES_MAESTRO = ["56", "58", "67", "502", "503", "506", "639", "5018", "6020"]
    
    static let PREFIXES_TROY = [
            "979200",
            "979201",
            "979202",
            "979203",
            "979204",
            "979205",
            "979206",
            "979207",
            "979208",
            "979209",
            "979210",
            "979211",
            "979212",
            "979213",
            "979214",
            "979215",
            "979216",
            "979217",
            "979218",
            "979219",
            "979220",
            "979221",
            "979222",
            "979223",
            "979224",
            "979225",
            "979226",
            "979227",
            "979228",
            "979229",
            "979230",
            "979231",
            "979232",
            "979233",
            "979234",
            "979235",
            "979236",
            "979237",
            "979238",
            "979239",
            "979240",
            "979241",
            "979242",
            "979243",
            "979244",
            "979245",
            "979246",
            "979247",
            "979248",
            "979249",
            "979250",
            "979251",
            "979252",
            "979253",
            "979254",
            "979255",
            "979256",
            "979257",
            "979258",
            "979259",
            "979260",
            "979261",
            "979262",
            "979263",
            "979264",
            "979265",
            "979266",
            "979267",
            "979268",
            "979269",
            "979270",
            "979271",
            "979272",
            "979273",
            "979274",
            "979275",
            "979276",
            "979277",
            "979278",
            "979279",
            "979280",
            "979281",
            "979282",
            "979283",
            "979284",
            "979285",
            "979286",
            "979287",
            "979288",
            "979289",
            "979290",
            "979291",
            "979292",
            "979293",
            "979294",
            "979295",
            "979296",
            "979297",
            "979298",
            "979299"
    ]
    
    static let PREFIX_DINACARD = "9891";
    static let PREFIXES_DINACARD: [String] = [
                PREFIX_DINACARD,
                "655670",
                "655671",
                "655672",
                "655673",
                "655674",
                "655675",
                "655676",
                "655677",
                "655678",
                "655679",
                "655680",
                "655681",
                "655682",
                "655683",
                "655684",
                "655685",
                "655686",
                "655687",
                "655688",
                "655689",
                "655690",
                "655691",
                "655692",
                "655693",
                "655694",
                "655695",
                "655696",
                "655697",
                "657371",
                "657372",
                "657373",
                "657374",
                "657375",
                "657376",
                "657377",
                "657378",
                "657379",
                "657380",
                "657381",
                "657382",
                "657383",
                "657384",
                "657385",
                "657386",
                "657387",
                "657388",
                "657389",
                "657390",
                "657391",
                "657392",
                "657393",
                "657394",
                "657395",
                "657396",
                "657397",
                "657398"
        ];
    
    static func isValidCVV(_ cvv: String) -> Bool {
        return isValidCVV(cvv, pan: nil)
    }
    
    static func isValidCVV(_ cvv: String, pan: String?) -> Bool {
        if cvv.count == 0 {
            return false
        }
        
        let cvvOnlyDigits = cvv.digits
        let detectedCardBrand = cardBrand(pan)
        
        return (detectedCardBrand == CardBrand.Unknown && cvvOnlyDigits.count >= 3 && cvvOnlyDigits.count <= 4 ) ||
            (detectedCardBrand == CardBrand.AmericanExpress && cvvOnlyDigits.count == 4) ||
            cvvOnlyDigits.count == 3
    }
    
    static func isValidCardHolderName(_ name: String) -> Bool {
        let v = name.trimmingCharacters(in: .whitespacesAndNewlines)
        return v.count > 0 && v.count <= 128
    }
    
    static func cardBrand(_ pan: String?) -> CardBrand {
        guard let pan = pan else {
            return CardBrand.Unknown
        }
        
        return possibleCardBrand(pan)
    }
    
    static func isValidPan(_ pan: String) -> Bool {
        let panOnlyDigits = pan.digits
        return isValidLuhnNumber(panOnlyDigits) && isValidCardLength(panOnlyDigits)
    }
    
    static func isValidCardLength(_ pan: String) -> Bool {
        let cardBrand = possibleCardBrand(pan)
        if cardBrand == .Unknown {
            return false
        }
        
        let length = pan.count
        
        switch cardBrand {
        case .AmericanExpress:
            return length == LENGTH_AMERICAN_EXPRESS
        case .DinersClub:
            return length == LENGTH_DINERS_CLUB
        case .Visa:
            return VISA_CARD_LENGTH.contains(length)
        case .Maestro:
            return MAESTRO_CARD_LENGTH.contains(length)
        default:
            return length == LENGTH_COMMON_CARD
        }
    }
    
    static func possibleCardBrand(_ pan: String) -> CardBrand {
        let spacelessCardNumber = pan.digits
        
        if (CSETextUtils.hasAnyPrefix(spacelessCardNumber, prefixes: PREFIXES_AMERICAN_EXPRESS)) {
            return CardBrand.AmericanExpress;
        } else if (CSETextUtils.hasAnyPrefix(spacelessCardNumber, prefixes: PREFIXES_DINACARD)) {
            return CardBrand.Dinacard;
        } else if (CSETextUtils.hasAnyPrefix(spacelessCardNumber,prefixes: PREFIXES_DISCOVER)) {
            return CardBrand.Discover;
        } else if (CSETextUtils.hasAnyPrefix(spacelessCardNumber, prefixes: PREFIXES_JCB)) {
            return CardBrand.Jcb;
        } else if (CSETextUtils.hasAnyPrefix(spacelessCardNumber, prefixes: PREFIXES_DINERS_CLUB)) {
            return CardBrand.DinersClub;
        } else if (CSETextUtils.hasAnyPrefix(spacelessCardNumber, prefixes: PREFIXES_VISA)) {
            return CardBrand.Visa;
        } else if (CSETextUtils.hasAnyPrefix(spacelessCardNumber, prefixes: PREFIXES_MAESTRO)) {
            return CardBrand.Maestro;
        } else if (CSETextUtils.hasAnyPrefix(spacelessCardNumber, prefixes: PREFIXES_MASTERCARD)) {
            return CardBrand.Mastercard;
        } else if (CSETextUtils.hasAnyPrefix(spacelessCardNumber, prefixes: PREFIXES_UNIONPAY)) {
            return CardBrand.UnionPay;
        } else if (CSETextUtils.hasAnyPrefix(spacelessCardNumber, prefixes: PREFIXES_TROY)) {
            return CardBrand.Troy;
        } else {
            return CardBrand.Unknown;
        }
    }
    
    static func isValidLuhnNumber(_ pan: String) -> Bool {
        return luhnCheck(pan)
    }
    
    static func isValidCardToken(_ token: String) -> Bool {
        return token.count >= 32 && token.count <= 64
    }
    
    static func isValidExpiry(month: Int, year: Int) -> Bool {
        if !validateExpMonth(month) {
            return false
        }
        
        let now = Date()
        
        if !validateExpYear(now: now, year: year) {
            return false
        }
        
        return !hasMonthPassed(year: year, month: month, now: now)
        
    }
    
    static func hasMonthPassed(year: Int, month: Int, now: Date) -> Bool {
        
        if hasYearPassed(year, now: now) {
            return true
        }
        
        let calendar = Calendar.current
        let normalizedYear = normalizeYear(year, now: now)
        
        return normalizedYear == calendar.component(.year, from: now) && month < calendar.component(.month, from: now)
    }
    
    static func validateExpMonth(_ month: Int) -> Bool {
        return month >= 1 && month <= 12
    }
    
    static func validateExpYear(now: Date, year: Int) -> Bool {
        return !hasYearPassed(year, now: now)
    }
    
    static func hasYearPassed(_ year: Int, now: Date) -> Bool {
        let normalized = normalizeYear(year, now: now)
        let calendar = Calendar.current
        return normalized < calendar.component(.year, from: now)
    }
    
    static func normalizeYear(_ year: Int, now: Date) -> Int {
        if year < 100 && year >= 0 {
            let calendar = Calendar.current
            let currentYear = calendar.component(.year, from: now)
            let prefix = Int("\(currentYear)"[0...1] + "00")!
            return prefix + year
        }
        
        return year
    }
    
    static func validateNonce(_ nonce: String) -> Bool {
        return nonce.count > 0 && nonce.count <= 16
    }
}

internal class CSETextUtils {
    static func hasAnyPrefix(_ number: String?, prefixes: [String]) -> Bool {
        guard let number = number else {
            return false
        }
        
        for prefix in prefixes {
            if number.starts(with: prefix) {
                return true
            }
        }
        
        return false
    }
}

internal func luhnCheck(_ number: String) -> Bool {
    var sum = 0
    let digitStrings = number.reversed().map { String($0) }

    for tuple in digitStrings.enumerated() {
        if let digit = Int(tuple.element) {
            let odd = tuple.offset % 2 == 1

            switch (odd, digit) {
            case (true, 9):
                sum += 9
            case (true, 0...8):
                sum += (digit * 2) % 9
            default:
                sum += digit
            }
        } else {
            return false
        }
    }
    return sum % 10 == 0
}

@objc(MsuCse)
class MsuCse: NSObject {
    private var _errors: [String] = []
        
    public  var errors: [String] {
        get {
            return _errors
        }
    }
//    private let cseApi: CSEApi
        
    public var hasErrors: Bool { errors.count > 0 }
    
//    public init(developmentMode: Bool) {
//        cseApi = CSEApiImpl(developmentMode: developmentMode)
//    }
    
    static let  LENGTH_COMMON_CARD = 16;
    static let  LENGTH_AMERICAN_EXPRESS = 15;
    static let  LENGTH_DINERS_CLUB = 14;
    static let MAESTRO_CARD_LENGTH = [12, 13, 14, 15, 16, 17, 18, 19]
    static let VISA_CARD_LENGTH = [16, 19]
    
    static let  PREFIXES_AMERICAN_EXPRESS = ["34", "37"]
    static let  PREFIXES_DISCOVER = ["60", "64", "65"]
    static let  PREFIXES_JCB = ["35"];
    static let  PREFIXES_DINERS_CLUB = ["300", "301", "302", "303", "304",
            "305", "309", "36", "38", "39"]
    static let  PREFIXES_VISA = ["4"];
    static let  PREFIXES_MASTERCARD = [
            "2221", "2222", "2223", "2224", "2225", "2226", "2227", "2228", "2229",
            "223", "224", "225", "226", "227", "228", "229",
            "23", "24", "25", "26",
            "270", "271", "2720",
            "50", "51", "52", "53", "54", "55", "67"
    ]
    
    static let  PREFIXES_UNIONPAY = ["62"]
    
    static let PREFIXES_MAESTRO = ["56", "58", "67", "502", "503", "506", "639", "5018", "6020"]
    
    static let PREFIXES_TROY = [
            "979200",
            "979201",
            "979202",
            "979203",
            "979204",
            "979205",
            "979206",
            "979207",
            "979208",
            "979209",
            "979210",
            "979211",
            "979212",
            "979213",
            "979214",
            "979215",
            "979216",
            "979217",
            "979218",
            "979219",
            "979220",
            "979221",
            "979222",
            "979223",
            "979224",
            "979225",
            "979226",
            "979227",
            "979228",
            "979229",
            "979230",
            "979231",
            "979232",
            "979233",
            "979234",
            "979235",
            "979236",
            "979237",
            "979238",
            "979239",
            "979240",
            "979241",
            "979242",
            "979243",
            "979244",
            "979245",
            "979246",
            "979247",
            "979248",
            "979249",
            "979250",
            "979251",
            "979252",
            "979253",
            "979254",
            "979255",
            "979256",
            "979257",
            "979258",
            "979259",
            "979260",
            "979261",
            "979262",
            "979263",
            "979264",
            "979265",
            "979266",
            "979267",
            "979268",
            "979269",
            "979270",
            "979271",
            "979272",
            "979273",
            "979274",
            "979275",
            "979276",
            "979277",
            "979278",
            "979279",
            "979280",
            "979281",
            "979282",
            "979283",
            "979284",
            "979285",
            "979286",
            "979287",
            "979288",
            "979289",
            "979290",
            "979291",
            "979292",
            "979293",
            "979294",
            "979295",
            "979296",
            "979297",
            "979298",
            "979299"
    ]
    
    static let PREFIX_DINACARD = "9891";
    static let PREFIXES_DINACARD: [String] = [
                PREFIX_DINACARD,
                "655670",
                "655671",
                "655672",
                "655673",
                "655674",
                "655675",
                "655676",
                "655677",
                "655678",
                "655679",
                "655680",
                "655681",
                "655682",
                "655683",
                "655684",
                "655685",
                "655686",
                "655687",
                "655688",
                "655689",
                "655690",
                "655691",
                "655692",
                "655693",
                "655694",
                "655695",
                "655696",
                "655697",
                "657371",
                "657372",
                "657373",
                "657374",
                "657375",
                "657376",
                "657377",
                "657378",
                "657379",
                "657380",
                "657381",
                "657382",
                "657383",
                "657384",
                "657385",
                "657386",
                "657387",
                "657388",
                "657389",
                "657390",
                "657391",
                "657392",
                "657393",
                "657394",
                "657395",
                "657396",
                "657397",
                "657398"
        ];
    
    @objc(isValidCVV:withPan:withResolver:withRejecter:)
    func isValidCVV(_ cvv: String, pan: String?, resolve:RCTPromiseResolveBlock,reject:RCTPromiseRejectBlock) -> Void {
        if cvv.count == 0 {
            resolve(false)
            return
        }

        let cvvOnlyDigits = cvv.digits
        let detectedCardBrand = cardBrand(pan)

        resolve((detectedCardBrand == CardBrand.Unknown && cvvOnlyDigits.count >= 3 && cvvOnlyDigits.count <= 4 ) ||
                (detectedCardBrand == CardBrand.AmericanExpress && cvvOnlyDigits.count == 4) ||
            cvvOnlyDigits.count == 3)
    }
    
    @objc(detectBrand:withResolver:withRejecter:)
    func detectBrand(_ pan: String, resolve:RCTPromiseResolveBlock,reject:RCTPromiseRejectBlock) -> Void {
        resolve(cardBrand(pan).rawValue)
    }
    
    @objc(isValidPan:withResolver:withRejecter:)
    func isValidPan(_ pan: String, resolve:RCTPromiseResolveBlock,reject:RCTPromiseRejectBlock) -> Void {
        let panOnlyDigits = pan.digits
        resolve(isValidLuhnNumber(panOnlyDigits) && isValidCardLength(panOnlyDigits))
    }
    
    @objc(isValidExpiry:withYear:withResolver:withRejecter:)
    func isValidExpiry(month: Int, year: Int, resolve:RCTPromiseResolveBlock,reject:RCTPromiseRejectBlock) -> Void {
        if !validateExpMonth(month) {
            resolve(false)
            return
        }
        
        let now = Date()
        
        if !validateExpYear(now: now, year: year) {
            resolve(false)
            return
        }
        
        resolve(!hasMonthPassed(year: year, month: month, now: now))
        
    }

    func cardBrand(_ pan: String?) -> CardBrand {
        guard let pan = pan else {
            return CardBrand.Unknown
        }

        return possibleCardBrand(pan)
    }

    func possibleCardBrand(_ pan: String) -> CardBrand {
        let spacelessCardNumber = pan.digits

        if (hasAnyPrefix(spacelessCardNumber, prefixes: MsuCse.PREFIXES_AMERICAN_EXPRESS)) {
            return CardBrand.AmericanExpress;
        } else if (hasAnyPrefix(spacelessCardNumber, prefixes: MsuCse.PREFIXES_DINACARD)) {
            return CardBrand.Dinacard;
        } else if (hasAnyPrefix(spacelessCardNumber,prefixes: MsuCse.PREFIXES_DISCOVER)) {
            return CardBrand.Discover;
        } else if (hasAnyPrefix(spacelessCardNumber, prefixes: MsuCse.PREFIXES_JCB)) {
            return CardBrand.Jcb;
        } else if (hasAnyPrefix(spacelessCardNumber, prefixes: MsuCse.PREFIXES_DINERS_CLUB)) {
            return CardBrand.DinersClub;
        } else if (hasAnyPrefix(spacelessCardNumber, prefixes: MsuCse.PREFIXES_VISA)) {
            return CardBrand.Visa;
        } else if (hasAnyPrefix(spacelessCardNumber, prefixes: MsuCse.PREFIXES_MAESTRO)) {
            return CardBrand.Maestro;
        } else if (hasAnyPrefix(spacelessCardNumber, prefixes: MsuCse.PREFIXES_MASTERCARD)) {
            return CardBrand.Mastercard;
        } else if (hasAnyPrefix(spacelessCardNumber, prefixes: MsuCse.PREFIXES_UNIONPAY)) {
            return CardBrand.UnionPay;
        } else if (hasAnyPrefix(spacelessCardNumber, prefixes: MsuCse.PREFIXES_TROY)) {
            return CardBrand.Troy;
        } else {
            return CardBrand.Unknown;
        }
    }

    func hasAnyPrefix(_ number: String?, prefixes: [String]) -> Bool {
        guard let number = number else {
            return false
        }

        for prefix in prefixes {
            if number.starts(with: prefix) {
                return true
            }
        }

        return false
    }
    
    func isValidCardLength(_ pan: String) -> Bool {
        let cardBrand = possibleCardBrand(pan)
        if cardBrand == CardBrand.Unknown {
            return false
        }
        
        let length = pan.count
        
        switch cardBrand {
        case CardBrand.AmericanExpress:
            return length == MsuCse.LENGTH_AMERICAN_EXPRESS
        case CardBrand.DinersClub:
            return length == MsuCse.LENGTH_DINERS_CLUB
        case CardBrand.Visa:
            return MsuCse.VISA_CARD_LENGTH.contains(length)
        case CardBrand.Maestro:
            return MsuCse.MAESTRO_CARD_LENGTH.contains(length)
        default:
            return length == MsuCse.LENGTH_COMMON_CARD
        }
    }
    
    func isValidLuhnNumber(_ pan: String) -> Bool {
        return luhnCheck(pan)
    }
    
    func luhnCheck(_ number: String) -> Bool {
        var sum = 0
        let digitStrings = number.reversed().map { String($0) }

        for tuple in digitStrings.enumerated() {
            if let digit = Int(tuple.element) {
                let odd = tuple.offset % 2 == 1

                switch (odd, digit) {
                case (true, 9):
                    sum += 9
                case (true, 0...8):
                    sum += (digit * 2) % 9
                default:
                    sum += digit
                }
            } else {
                return false
            }
        }
        return sum % 10 == 0
    }
    
    func validateExpMonth(_ month: Int) -> Bool {
        return month >= 1 && month <= 12
    }
    
    func validateExpYear(now: Date, year: Int) -> Bool {
            return !hasYearPassed(year, now: now)
        }
        
    func hasYearPassed(_ year: Int, now: Date) -> Bool {
        let normalized = normalizeYear(year, now: now)
        let calendar = Calendar.current
        return normalized < calendar.component(.year, from: now)
    }
    
    func hasMonthPassed(year: Int, month: Int, now: Date) -> Bool {
            
        if hasYearPassed(year, now: now) {
            return true
        }
        
        let calendar = Calendar.current
        let normalizedYear = normalizeYear(year, now: now)
        
        return normalizedYear == calendar.component(.year, from: now) && month < calendar.component(.month, from: now)
    }
    
    func normalizeYear(_ year: Int, now: Date) -> Int {
        if year < 100 && year >= 0 {
            let calendar = Calendar.current
            let currentYear = calendar.component(.year, from: now)
            let prefix = Int("\(currentYear)"[0...1] + "00")!
            return prefix + year
        }
        
        return year
    }
    
    @objc(multiply:withB:withResolver:withRejecter:)
    func multiply(a: Float, b: Float, resolve:RCTPromiseResolveBlock,reject:RCTPromiseRejectBlock) -> Void {
        resolve(a*b)
    }
    
    @objc(encrypt:withName:withExpiryYear:withExpiryMonth:withCVV:withNonce:withResolver:withRejecter:)
    private func encrypt(pan: String, cardHolderName: String, expiryYear: Int, expiryMonth: Int, cvv: String, nonce: String, resolve: @escaping RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void {
            let request: EncryptRequest = CardEncryptRequest(pan: pan, cardHolderName: cardHolderName, year: expiryYear, month: expiryMonth, cvv: cvv, nonce: nonce);
            _errors = []
            if !request.validate() {
                _errors = request.errors()
                DispatchQueue.main.async {resolve("Error: Validation failed")}
            } else {
                DispatchQueue.global(qos: .background).async { [weak self] in
                    
                    let cseApi = CSEApiImpl(developmentMode: true)
                    cseApi.fetchPublicKey {
                        r in
                        switch r {
                        case .error(let e):
                            DispatchQueue.main.async { resolve("Error: Cannot fetch public key") }
                        case .result(let publicKey):
                            let encrypted = RSAEncryption.encrypt(publicKey, plain: request.plain())
                            switch encrypted {
                            case .error(let e):
                                DispatchQueue.main.async { resolve("Error: Unknown error") }
                            case .success(let encrypted):
                                DispatchQueue.main.async { resolve(encrypted) }
                            }
                        }
                        return ""
                    }
                }
            }
        }
}

internal protocol CSEApi {
    func fetchPublicKey(_ callback: @escaping (PublicKeyFetchResult) -> String)
}

internal class CSEApiImpl: CSEApi {
    
    let developmentMode: Bool
    var endpoint: String {
        if developmentMode {
           return  "https://test.merchantsafeunipay.com/msu/cse/publickey"
        } else {
            return "https://merchantsafeunipay.com/msu/cse/publickey"
        }
    }
    
    var publicKey: String?
    
    init(developmentMode: Bool) {
        self.developmentMode = developmentMode
    }
    
    func fetchPublicKey(_ callback: @escaping (PublicKeyFetchResult) -> String) {
        
        if let publicKey = self.publicKey {
            callback(.result(publicKey))
            return
        }
        
        let url = URL(string: endpoint)!
        let task = URLSession.shared.dataTask(with: url) { [weak self] (data, response, error)  in
            if let error = error {
                callback(PublicKeyFetchResult.error(error))
            } else {
                if let data = data {
                    do {
                        let result = try JSONSerialization.jsonObject(with: data, options: []) as? [String: String]
                        
                        guard let jsonObject = result else {
                            callback(.error(EncryptionError.publicKeyEncodingFailed("Decoding failed, result nil")))
                            return
                        }
                        
                        guard let publicKey = jsonObject["publicKey"] else {
                            callback(.error(EncryptionError.publicKeyEncodingFailed("Decoding failed, missing public key")))
                            return
                        }
                        
                        self?.publicKey = publicKey
                        
                        callback(.result(publicKey))
                        
                    } catch {
                            callback(.error(EncryptionError.publicKeyEncodingFailed(error.localizedDescription)))
                    }
                } else {
                    callback(.error(EncryptionError.publicKeyEncodingFailed("Decoding failed")))
                }
            }
        }
        task.resume()
    }
}

enum PublicKeyFetchResult {
    case result(String)
    case error(Error)
}

public protocol EncryptRequest {
    func validate() -> Bool
    func errors() -> [String]
    func plain() -> String
}

public class CvvEncryptionRequest: EncryptRequest {
    let cvv: String
    let nonce: String
    
    init(cvv: String, nonce: String) {
        self.cvv = cvv
        self.nonce = nonce
    }
    
    private var _errors: [String] = []
    
    public func validate() -> Bool {
        _errors = []
        
        if !CardUtils.isValidCVV(cvv) {
            _errors.append("CVV_INVALID")
        }
        
        if !CardUtils.validateNonce(nonce) {
            _errors.append("NONCE_MISSING_OR_INVALID")
        }
        
        return _errors.isEmpty
    }
    
    public func errors() -> [String] {
        return _errors
    }
    
    public func plain() -> String {
        return "c=\(cvv)&n=\(nonce)"
    }
}

public class CardEncryptRequest: EncryptRequest {
    let pan: String
    let cardHolderName: String
    let year: Int
    let month: Int
    let cvv: String
    let nonce: String
    
    private var _errors: [String] = []
    
    public init(pan: String, cardHolderName: String, year: Int, month: Int, cvv: String, nonce: String) {
        self.pan = pan.digits
        self.cardHolderName = cardHolderName
        self.year = year
        self.month = month
        self.cvv = cvv.digits
        self.nonce = nonce
    }
    
    public func validate() -> Bool {
        _errors = []
        
        if !CardUtils.isValidPan(pan) {
            _errors.append("PAN_INVALID")
        }
        
        if !CardUtils.isValidExpiry(month: month, year: year) {
            _errors.append("EXPIRY_INVALID")
        }
        
        if !CardUtils.isValidCardHolderName(cardHolderName) {
            _errors.append("CARD_HOLDER_NAME_INVALID")
        }
        
        if !CardUtils.isValidCVV(cvv, pan: pan) {
            _errors.append("CVV_INVALID")
        }
        
        if !CardUtils.validateNonce(nonce) {
            _errors.append("NONCE_MISSING_OR_INVALID")
        }
        
        return _errors.isEmpty
    }
    
    public func errors() -> [String] {
        return _errors
    }
    
    private static func paddedMonth(_ month: Int) -> String {
        if (month < 10) {
            return "0\(month)"
        } else {
            return "\(month)"
        }
    }
    
    public func plain() -> String {
        return "p=\(pan)&y=\(year)&m=\(CardEncryptRequest.paddedMonth(month))&c=\(cvv)&cn=\(cardHolderName)&n=\(nonce)"
    }
}

public typealias EncryptCallback = (EncryptResult) -> Void

public enum EncryptResult {
    case success(String)
    case error(EncryptionError)
}

public enum EncryptionError: Error {
    case requestFailed
    case unknownException(Error)
    case validationFailed
    case publicKeyEncodingFailed(String)
    case encryptionFailed(String)
}

extension EncryptionError {
public static func ==(lhs: EncryptionError, rhs:EncryptionError) -> Bool {
    switch lhs {
    case .requestFailed:
        switch rhs {
        case .requestFailed:
            return true
        default:
            return false
        }
    case .validationFailed:
        switch rhs {
        case .validationFailed:
            return true
        default:
            return false
        }
    case .encryptionFailed(let a):
        switch rhs {
        case .encryptionFailed(let b):
            return a == b
        default:
            return false
        }
        
    case .publicKeyEncodingFailed(let a):
        switch rhs {
        case .publicKeyEncodingFailed(let b):
            return a == b
        default:
            return false
        }
        
    case .unknownException:
        switch rhs {
        case .unknownException:
            return true
        default:
            return false
        }
    }
    
    }
}

extension String {
    var digits: String {
        return components(separatedBy: CharacterSet.decimalDigits.inverted)
            .joined()
    }
}

extension String {
  subscript(_ i: Int) -> String {
    let idx1 = index(startIndex, offsetBy: i)
    let idx2 = index(idx1, offsetBy: 1)
    return String(self[idx1..<idx2])
  }

  subscript (r: Range<Int>) -> String {
    let start = index(startIndex, offsetBy: r.lowerBound)
    let end = index(startIndex, offsetBy: r.upperBound)
    return String(self[start ..< end])
  }

  subscript (r: CountableClosedRange<Int>) -> String {
    let startIndex =  self.index(self.startIndex, offsetBy: r.lowerBound)
    let endIndex = self.index(startIndex, offsetBy: r.upperBound - r.lowerBound)
    return String(self[startIndex...endIndex])
  }
}
