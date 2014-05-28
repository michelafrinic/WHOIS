package net.ripe.db.whois.common.domain.attrs;


import org.junit.Test;

import static net.ripe.db.whois.common.domain.attrs.InetnumStatus.*;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

public class InetnumStatusTest {

    @Test
    public void parentVerification() {
        assertThat(ASSIGNED_PA.worksWithParentStatus(ASSIGNED_PA, true), is(true));
        assertThat(ASSIGNED_PA.worksWithParentStatus(SUB_ALLOCATED_PA, true), is(true));
        assertThat(ASSIGNED_PA.worksWithParentStatus(ALLOCATED_UNSPECIFIED, true), is(true));

        assertThat(SUB_ALLOCATED_PA.worksWithParentStatus(ALLOCATED_PA, true), is(true));
        assertThat(SUB_ALLOCATED_PA.worksWithParentStatus(SUB_ALLOCATED_PA, true), is(true));

        assertThat(ALLOCATED_UNSPECIFIED.worksWithParentStatus(ALLOCATED_UNSPECIFIED, true), is(true));
        assertThat(ALLOCATED_PA.worksWithParentStatus(ALLOCATED_UNSPECIFIED, true), is(true));

        assertThat(ASSIGNED_PI.worksWithParentStatus(ALLOCATED_UNSPECIFIED, true), is(true));
        assertThat(ASSIGNED_PI.worksWithParentStatus(ASSIGNED_PI, false), is(true));
    }

    @Test
    public void allowedOrgTypesChecks() {
        assertThat(ALLOCATED_PA.isValidOrgType(OrgType.LIR), is(true));
        assertThat(ALLOCATED_PA.isValidOrgType(OrgType.RIR), is(true));
        assertThat(ALLOCATED_PA.isValidOrgType(OrgType.IANA), is(true));

        assertThat(ALLOCATED_UNSPECIFIED.isValidOrgType(OrgType.LIR), is(true));
        assertThat(ALLOCATED_UNSPECIFIED.isValidOrgType(OrgType.RIR), is(true));
        assertThat(ALLOCATED_UNSPECIFIED.isValidOrgType(OrgType.IANA), is(true));
        assertThat(ALLOCATED_UNSPECIFIED.isValidOrgType(OrgType.OTHER), is(false));

        assertThat(SUB_ALLOCATED_PA.isValidOrgType(OrgType.OTHER), is(true));
        assertThat(SUB_ALLOCATED_PA.isValidOrgType(OrgType.LIR), is(true));

        assertThat(ASSIGNED_PA.isValidOrgType(OrgType.OTHER), is(true));
        assertThat(ASSIGNED_PA.isValidOrgType(OrgType.LIR), is(true));

        assertThat(ASSIGNED_PI.isValidOrgType(OrgType.RIR), is(true));
        assertThat(ASSIGNED_PI.isValidOrgType(OrgType.LIR), is(true));
        assertThat(ASSIGNED_PI.isValidOrgType(OrgType.OTHER), is(true));
    }

    @Test
    public void needsEndMaintainerAuthorisation() {
        assertThat(InetnumStatus.ASSIGNED_PI.requiresRsMaintainer(), is(false));
        assertThat(InetnumStatus.SUB_ALLOCATED_PA.requiresRsMaintainer(), is(false));
    }

    @Test
    public void needsAllocMaintainerAuthorization() {
        for (final InetnumStatus inetnumStatus : InetnumStatus.values()) {
            assertThat(inetnumStatus.requiresAllocMaintainer(), is(false));
        }
    }

    @Test
    public void needsOrgReference() {
        assertThat(ALLOCATED_PA.needsOrgReference(), is(true));
        assertThat(ALLOCATED_UNSPECIFIED.needsOrgReference(), is(true));
        assertThat(SUB_ALLOCATED_PA.needsOrgReference(), is(false));
        assertThat(ASSIGNED_PA.needsOrgReference(), is(false));
        assertThat(ASSIGNED_PI.needsOrgReference(), is(false));
    }
}