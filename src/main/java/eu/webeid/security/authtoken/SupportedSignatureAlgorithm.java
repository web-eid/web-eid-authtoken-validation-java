package eu.webeid.security.authtoken;

public class SupportedSignatureAlgorithm {
    private String cryptoAlgorithm;
    private String hashFunction;
    private String paddingScheme;

    public String getCryptoAlgorithm() {
        return cryptoAlgorithm;
    }

    public void setCryptoAlgorithm(String cryptoAlgorithm) {
        this.cryptoAlgorithm = cryptoAlgorithm;
    }

    public String getHashFunction() {
        return hashFunction;
    }

    public void setHashFunction(String hashFunction) {
        this.hashFunction = hashFunction;
    }

    public String getPaddingScheme() {
        return paddingScheme;
    }

    public void setPaddingScheme(String paddingScheme) {
        this.paddingScheme = paddingScheme;
    }
}
