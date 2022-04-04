package me.youngforest.totp;

import java.lang.reflect.UndeclaredThrowableException;
import java.security.GeneralSecurityException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.util.TimeZone;
import java.time.Instant;

import java.util.*;
import com.microsoft.azure.functions.annotation.*;
import com.microsoft.azure.functions.*;

/**
 * Azure Functions with HTTP Trigger.
 */
public class TOTPGenerator {

    /**
     * This method uses the JCE to provide the crypto algorithm.
     * HMAC computes a Hashed Message Authentication Code with the
     * crypto hash algorithm as a parameter.
     *
     * @param crypto:   the crypto algorithm (HmacSHA1, HmacSHA256,
     *                  HmacSHA512)
     * @param keyBytes: the bytes to use for the HMAC key
     * @param text:     the message or text to be authenticated
     */
    private static byte[] hmac_sha(String crypto, byte[] keyBytes,
            byte[] text) {
        try {
            Mac hmac;
            hmac = Mac.getInstance(crypto);
            SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
            hmac.init(macKey);
            return hmac.doFinal(text);
        } catch (GeneralSecurityException gse) {
            throw new UndeclaredThrowableException(gse);
        }
    }

    /**
     * This method converts a HEX string to Byte[]
     *
     * @param hex: the HEX string
     *
     * @return: a byte array
     */

    private static byte[] hexStr2Bytes(String hex) {
        // Adding one byte to get the right conversion
        // Values starting with "0" can be converted
        byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();

        // Copy all the REAL bytes, not the "first"
        byte[] ret = new byte[bArray.length - 1];
        for (int i = 0; i < ret.length; i++)
            ret[i] = bArray[i + 1];
        return ret;
    }

    private static final int[] DIGITS_POWER
    // 0 1 2 3 4 5 6 7 8 9 10
            = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000, 1000000000 };

    /**
     * This method generates a TOTP value for the given
     * set of parameters.
     *
     * @param key:          the shared secret, HEX encoded
     * @param time:         a value that reflects a time
     * @param returnDigits: number of digits to return
     *
     * @return: a numeric String in base 10 that includes
     *          {@link truncationDigits} digits
     */

    public static String generateTOTP(String key,
            String time,
            String returnDigits) {
        return generateTOTP(key, time, returnDigits, "HmacSHA1");
    }

    /**
     * This method generates a TOTP value for the given
     * set of parameters.
     *
     * @param key:          the shared secret, HEX encoded
     * @param time:         a value that reflects a time
     * @param returnDigits: number of digits to return
     *
     * @return: a numeric String in base 10 that includes
     *          {@link truncationDigits} digits
     */

    public static String generateTOTP256(String key,
            String time,
            String returnDigits) {
        return generateTOTP(key, time, returnDigits, "HmacSHA256");
    }

    /**
     * This method generates a TOTP value for the given
     * set of parameters.
     *
     * @param key:          the shared secret, HEX encoded
     * @param time:         a value that reflects a time
     * @param returnDigits: number of digits to return
     *
     * @return: a numeric String in base 10 that includes
     *          {@link truncationDigits} digits
     */

    public static String generateTOTP512(String key,
            String time,
            String returnDigits) {
        return generateTOTP(key, time, returnDigits, "HmacSHA512");
    }

    /**
     * This method generates a TOTP value for the given
     * set of parameters.
     *
     * @param key:          the shared secret, HEX encoded
     * @param time:         a value that reflects a time
     * @param returnDigits: number of digits to return
     * @param crypto:       the crypto function to use
     *
     * @return: a numeric String in base 10 that includes
     *          {@link truncationDigits} digits
     */

    public static String generateTOTP(String key,
            String time,
            String returnDigits,
            String crypto) {
        int codeDigits = Integer.decode(returnDigits).intValue();
        String result = null;

        // Using the counter
        // First 8 bytes are for the movingFactor
        // Compliant with base RFC 4226 (HOTP)
        while (time.length() < 16)
            time = "0" + time;

        // Get the HEX in a Byte[]
        byte[] msg = hexStr2Bytes(time);
        byte[] k = hexStr2Bytes(key);
        byte[] hash = hmac_sha(crypto, k, msg);

        // put selected bytes into result int
        int offset = hash[hash.length - 1] & 0xf;

        int binary = ((hash[offset] & 0x7f) << 24) |
                ((hash[offset + 1] & 0xff) << 16) |
                ((hash[offset + 2] & 0xff) << 8) |
                (hash[offset + 3] & 0xff);

        int otp = binary % DIGITS_POWER[codeDigits];

        result = Integer.toString(otp);
        while (result.length() < codeDigits) {
            result = "0" + result;
        }
        return result;
    }

    private String stringToHexadecimal(final String input) {
        StringBuffer sb = new StringBuffer();
        //Converting string to character array
        char ch[] = input.toCharArray();
        for(int i = 0; i < ch.length; i++) {
           String hexString = Integer.toHexString(ch[i]);
           sb.append(hexString);
        }
        return sb.toString();
    }

    /**
     * This function listens at endpoint "/api/TOTPGenerator". Two ways to invoke it using "curl" command in bash:
     * 1. curl -d "HTTP Body" {your host}/api/TOTPGenerator
     * 2. curl {your host}/api/TOTPGenerator?name=HTTP%20Query
     */
    @FunctionName("TOTPGenerator")
    public HttpResponseMessage run(
            @HttpTrigger(name = "req", methods = {HttpMethod.GET, HttpMethod.POST}, authLevel = AuthorizationLevel.FUNCTION) HttpRequestMessage<Optional<String>> request,
            final ExecutionContext context) {
        context.getLogger().info("Java HTTP trigger processed a request.");

        // Parse query parameter
        Map<String, String> queryParams = request.getQueryParameters();
        System.out.println(queryParams);
        long T0 = Long.parseLong(request.getQueryParameters().get("T0"));
        long X = Long.parseLong(queryParams.get("X"));
        String sharedSecret = request.getQueryParameters().get("sharedSecret");
        sharedSecret = stringToHexadecimal(sharedSecret);
        int digits = Integer.parseInt(request.getQueryParameters().get("digits"));
        if (digits <= 0 || digits > 10) {
            return request.createResponseBuilder(HttpStatus.BAD_REQUEST).body("Please pass a digits(from 1 to 10 inclusive) on the query string").build();
        }
        String hashAlgorithm = request.getQueryParameters().get("hashAlgorithm");
        if (!hashAlgorithm.equals("HmacSHA1") && !hashAlgorithm.equals("HmacSHA256") && !hashAlgorithm.equals("HmacSHA512")) {
            return request.createResponseBuilder(HttpStatus.BAD_REQUEST).body("Please pass a hashAlgorithm (HmacSHA1, HmacSHA256 or HmacSHA512) on the query string").build();
        }
        long timestamp = Long.parseLong(request.getQueryParameters().get("timestamp"));

        long T = (timestamp - T0) / X;
        String steps = Long.toHexString(T).toUpperCase();
        while (steps.length() < 16)
            steps = "0" + steps;

        String ans = generateTOTP(sharedSecret, steps, Integer.toString(digits), hashAlgorithm);
        return request.createResponseBuilder(HttpStatus.OK).body(ans).build();
    }
}
