// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.resilientocsp.exceptions;

import eu.webeid.ocsp.exceptions.UserCertificateOCSPCheckFailedException;
import eu.webeid.security.validator.ValidationInfo;

public class ResilientUserCertificateOCSPCheckFailedException extends UserCertificateOCSPCheckFailedException {

    private ValidationInfo validationInfo;

    public ResilientUserCertificateOCSPCheckFailedException(String message) {
        this(message, null);
    }

    public ResilientUserCertificateOCSPCheckFailedException(ValidationInfo validationInfo) {
        super();
        this.validationInfo = validationInfo;
    }

    public ResilientUserCertificateOCSPCheckFailedException(String message, ValidationInfo validationInfo) {
        super(message);
        this.validationInfo = validationInfo;
    }

    public ValidationInfo getValidationInfo() {
        return validationInfo;
    }

    public void setValidationInfo(ValidationInfo validationInfo) {
        this.validationInfo = validationInfo;
    }
}
