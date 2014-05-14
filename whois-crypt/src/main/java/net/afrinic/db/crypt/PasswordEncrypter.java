package net.afrinic.db.crypt;

import org.apache.commons.codec.digest.Md5Crypt;
import org.apache.commons.codec.digest.UnixCrypt;

/**
 * Created by yogesh on 5/13/14.
 */
public class PasswordEncrypter {

    public static void main(String[] args) throws Exception {

        String scheme;
        String offeredPassword;
        byte[] offeredPasswordBytes;
        String encryptedPassword = null;

        if (args.length >= 2) {
            scheme = args[0].trim().toLowerCase();
            offeredPassword = args[1];
            offeredPasswordBytes = offeredPassword.getBytes();
        } else {
            printUsage();
            return;
        }

        if (args.length == 2) {
            if ("crypt".equals(scheme)) {
                encryptedPassword = UnixCrypt.crypt(offeredPasswordBytes);
            } else if ("md5".equals(scheme)) {
                encryptedPassword = Md5Crypt.md5Crypt(offeredPasswordBytes);
            } else {
                printUsage();
                return;
            }
        } else if (args.length == 3) {
            /*
             * Meaning of salt:
             * For md5,   salt = "$1$" + 8 characters before '$' in hash
             * For crypt, salt = first 2 characters in hash
             *
             * @see http://commons.apache.org/proper/commons-codec/apidocs/index.html?org/apache/commons/codec/digest/Crypt.html
             */
            String salt = args[2];
            if ("crypt-salt".equals(scheme)) {
                encryptedPassword = UnixCrypt.crypt(offeredPasswordBytes, salt);
            } else if ("md5-salt".equals(scheme)) {
                encryptedPassword = Md5Crypt.md5Crypt(offeredPasswordBytes, salt);
            } else {
                printUsage();
                return;
            }
        }

        //System.out.println(scheme + "|" + offeredPassword + "|" + encryptedPassword);
        System.out.println(encryptedPassword);
    }

    public static void printUsage() {
        System.out.println("Usage: java -jar <jar file name> <scheme, either 'crypt' or 'md5'> <password to encrypt>");
    }
}