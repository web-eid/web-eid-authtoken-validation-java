// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.resilientocsp.exceptions;

import eu.webeid.ocsp.exceptions.UserCertificateRevokedException;
import eu.webeid.security.validator.ValidationInfo;

public class ResilientUserCertificateRevokedException extends UserCertificateRevokedException {

    private ValidationInfo validationInfo;

    public ResilientUserCertificateRevokedException(ValidationInfo validationInfo) {
        this.validationInfo = validationInfo;
    }

    public ValidationInfo getValidationInfo() {
        return validationInfo;
    }

    public void setValidationInfo(ValidationInfo validationInfo) {
        this.validationInfo = validationInfo;
    }
}
