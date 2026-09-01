// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.validator.certvalidators;

import eu.webeid.security.exceptions.AuthTokenException;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class SubjectCertificateValidatorBatch {

    private final List<SubjectCertificateValidator> validatorList;

    public static SubjectCertificateValidatorBatch createFrom(SubjectCertificateValidator... validatorList) {
        final List<SubjectCertificateValidator> list = new ArrayList<>();
        Collections.addAll(list, validatorList);
        return new SubjectCertificateValidatorBatch(list);
    }

    public void executeFor(X509Certificate subjectCertificate) throws AuthTokenException {
        for (final SubjectCertificateValidator validator : validatorList) {
            validator.validate(subjectCertificate);
        }
    }

    public SubjectCertificateValidatorBatch addOptional(boolean condition, SubjectCertificateValidator optionalValidator) {
        if (condition) {
            validatorList.add(optionalValidator);
        }
        return this;
    }

    private SubjectCertificateValidatorBatch(List<SubjectCertificateValidator> validatorList) {
        this.validatorList = validatorList;
    }
}
