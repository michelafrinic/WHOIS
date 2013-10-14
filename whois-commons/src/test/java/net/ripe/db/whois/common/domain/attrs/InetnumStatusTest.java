package net.ripe.db.whois.common.domain.attrs;


import org.junit.Test;

import static net.ripe.db.whois.common.domain.attrs.InetnumStatus.*;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

public class InetnumStatusTest {

    @Test
    public void parentVerification() {
        assertThat(ASSIGNED_PA.worksWithParentStatus(ASSIGNED_PA, true), is(true));
        assertThat(ASSIGNED_PA.worksWithParentStatus(EARLY_REGISTRATION, true), is(true));
        assertThat(ASSIGNED_PA.worksWithParentStatus(SUB_ALLOCATED_PA, true), is(true));
        assertThat(ASSIGNED_PA.worksWithParentStatus(LIR_PARTITIONED_PI, true), is(false));
        assertThat(ASSIGNED_PA.worksWithParentStatus(LIR_PARTITIONED_PA, true), is(true));
        assertThat(ASSIGNED_PA.worksWithParentStatus(ALLOCATED_UNSPECIFIED, true), is(true));

        assertThat(SUB_ALLOCATED_PA.worksWithParentStatus(ALLOCATED_PA, true), is(true));
        assertThat(SUB_ALLOCATED_PA.worksWithParentStatus(LIR_PARTITIONED_PA, true), is(true));
        assertThat(SUB_ALLOCATED_PA.worksWithParentStatus(SUB_ALLOCATED_PA, true), is(true));
        assertThat(SUB_ALLOCATED_PA.worksWithParentStatus(EARLY_REGISTRATION, false), is(true));

        assertThat(LIR_PARTITIONED_PA.worksWithParentStatus(ALLOCATED_UNSPECIFIED, true), is(true));
        assertThat(LIR_PARTITIONED_PA.worksWithParentStatus(ALLOCATED_PI, true), is(false));
        assertThat(LIR_PARTITIONED_PA.worksWithParentStatus(ALLOCATED_PA, true), is(true));
        assertThat(LIR_PARTITIONED_PA.worksWithParentStatus(LIR_PARTITIONED_PI, true), is(false));
        assertThat(LIR_PARTITIONED_PA.worksWithParentStatus(LIR_PARTITIONED_PA, true), is(true));
        assertThat(LIR_PARTITIONED_PA.worksWithParentStatus(EARLY_REGISTRATION, true), is(true));
        assertThat(LIR_PARTITIONED_PA.worksWithParentStatus(SUB_ALLOCATED_PA, true), is(true));

        assertThat(LIR_PARTITIONED_PI.worksWithParentStatus(EARLY_REGISTRATION, true), is(true));
        assertThat(LIR_PARTITIONED_PI.worksWithParentStatus(ALLOCATED_UNSPECIFIED, true), is(true));
        assertThat(LIR_PARTITIONED_PI.worksWithParentStatus(LIR_PARTITIONED_PI, true), is(true));
        assertThat(LIR_PARTITIONED_PI.worksWithParentStatus(ALLOCATED_PI, true), is(true));
        assertThat(LIR_PARTITIONED_PI.worksWithParentStatus(LIR_PARTITIONED_PA, true), is(false));

        assertThat(ALLOCATED_PI.worksWithParentStatus(ALLOCATED_UNSPECIFIED, true), is(true));
        assertThat(ALLOCATED_UNSPECIFIED.worksWithParentStatus(ALLOCATED_UNSPECIFIED, true), is(true));
        assertThat(ALLOCATED_PA.worksWithParentStatus(ALLOCATED_UNSPECIFIED, true), is(true));
        assertThat(ALLOCATED_PA.worksWithParentStatus(LIR_PARTITIONED_PA, true), is(false));

        assertThat(ASSIGNED_PI.worksWithParentStatus(ALLOCATED_UNSPECIFIED, true), is(true));
        assertThat(ASSIGNED_PI.worksWithParentStatus(ASSIGNED_PI, false), is(true));
        assertThat(ASSIGNED_PI.worksWithParentStatus(EARLY_REGISTRATION, false), is(true));
        assertThat(ASSIGNED_PI.worksWithParentStatus(EARLY_REGISTRATION, false), is(true));
        assertThat(ASSIGNED_PI.worksWithParentStatus(LIR_PARTITIONED_PI, false), is(true));
        assertThat(ASSIGNED_PI.worksWithParentStatus(ALLOCATED_PI, false), is(true));
        assertThat(ASSIGNED_PI.worksWithParentStatus(LIR_PARTITIONED_PA, false), is(false));

        assertThat(ASSIGNED_ANYCAST.worksWithParentStatus(ALLOCATED_UNSPECIFIED, false), is(true));
        assertThat(ASSIGNED_ANYCAST.worksWithParentStatus(ALLOCATED_PI, false), is(true));
        assertThat(ASSIGNED_ANYCAST.worksWithParentStatus(SUB_ALLOCATED_PA, false), is(false));

        assertThat(EARLY_REGISTRATION.worksWithParentStatus(ALLOCATED_UNSPECIFIED, false), is(true));
        assertThat(EARLY_REGISTRATION.worksWithParentStatus(EARLY_REGISTRATION, false), is(true));
        assertThat(EARLY_REGISTRATION.worksWithParentStatus(ALLOCATED_PA, false), is(false));
    }

    @Test
    public void allowedOrgTypesChecks() {
        assertThat(ALLOCATED_PI.isValidOrgType(OrgType.LIR), is(true));
        assertThat(ALLOCATED_PI.isValidOrgType(OrgType.RIR), is(true));
        assertThat(ALLOCATED_PI.isValidOrgType(OrgType.IANA), is(true));
        //assertThat(ALLOCATED_PI.isValidOrgType(OrgType.WHITEPAGES), is(false));/*-AFRINIC-*/

        assertThat(ALLOCATED_PA.isValidOrgType(OrgType.LIR), is(true));
        assertThat(ALLOCATED_PA.isValidOrgType(OrgType.RIR), is(true));
        assertThat(ALLOCATED_PA.isValidOrgType(OrgType.IANA), is(true));
        //assertThat(ALLOCATED_PA.isValidOrgType(OrgType.DIRECT_ASSIGNMENT), is(false));/*-AFRINIC-*/

        assertThat(ALLOCATED_UNSPECIFIED.isValidOrgType(OrgType.LIR), is(true));
        assertThat(ALLOCATED_UNSPECIFIED.isValidOrgType(OrgType.RIR), is(true));
        assertThat(ALLOCATED_UNSPECIFIED.isValidOrgType(OrgType.IANA), is(true));
        assertThat(ALLOCATED_UNSPECIFIED.isValidOrgType(OrgType.OTHER), is(false));

        assertThat(LIR_PARTITIONED_PA.isValidOrgType(OrgType.OTHER), is(true));
        assertThat(LIR_PARTITIONED_PA.isValidOrgType(OrgType.LIR), is(true));
        //assertThat(LIR_PARTITIONED_PA.isValidOrgType(OrgType.NIR), is(false));/*-AFRINIC-*/

        assertThat(LIR_PARTITIONED_PI.isValidOrgType(OrgType.OTHER), is(true));
        assertThat(LIR_PARTITIONED_PI.isValidOrgType(OrgType.LIR), is(true));
        assertThat(LIR_PARTITIONED_PI.isValidOrgType(OrgType.RIR), is(false));

        assertThat(SUB_ALLOCATED_PA.isValidOrgType(OrgType.OTHER), is(true));
        assertThat(SUB_ALLOCATED_PA.isValidOrgType(OrgType.LIR), is(true));

        assertThat(ASSIGNED_PA.isValidOrgType(OrgType.OTHER), is(true));
        assertThat(ASSIGNED_PA.isValidOrgType(OrgType.LIR), is(true));
        //assertThat(ASSIGNED_PA.isValidOrgType(OrgType.WHITEPAGES), is(false));/*-AFRINIC-*/

        assertThat(ASSIGNED_ANYCAST.isValidOrgType(OrgType.OTHER), is(true));
        assertThat(ASSIGNED_ANYCAST.isValidOrgType(OrgType.LIR), is(true));
        assertThat(ASSIGNED_ANYCAST.isValidOrgType(OrgType.IANA), is(false));

        assertThat(EARLY_REGISTRATION.isValidOrgType(OrgType.OTHER), is(true));
        assertThat(EARLY_REGISTRATION.isValidOrgType(OrgType.LIR), is(true));
        //assertThat(EARLY_REGISTRATION.isValidOrgType(OrgType.WHITEPAGES), is(false));/*-AFRINIC-*/

        assertThat(ASSIGNED_PI.isValidOrgType(OrgType.RIR), is(true));
        assertThat(ASSIGNED_PI.isValidOrgType(OrgType.LIR), is(true));
        assertThat(ASSIGNED_PI.isValidOrgType(OrgType.OTHER), is(true));
        //assertThat(ASSIGNED_PI.isValidOrgType(OrgType.NIR), is(false));/*-AFRINIC-*/
        //assertThat(ASSIGNED_PI.isValidOrgType(OrgType.DIRECT_ASSIGNMENT), is(false));/*-AFRINIC-*/
    }

    @Test
    public void needsEndMaintainerAuthorisation() {
        assertThat(InetnumStatus.ASSIGNED_ANYCAST.requiresRsMaintainer(), is(true));
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
        assertThat(ALLOCATED_PI.needsOrgReference(), is(true));
        assertThat(ALLOCATED_UNSPECIFIED.needsOrgReference(), is(true));
        assertThat(LIR_PARTITIONED_PA.needsOrgReference(), is(false));
        assertThat(LIR_PARTITIONED_PI.needsOrgReference(), is(false));
        assertThat(SUB_ALLOCATED_PA.needsOrgReference(), is(false));
        assertThat(ASSIGNED_PA.needsOrgReference(), is(false));
        assertThat(ASSIGNED_PI.needsOrgReference(), is(false));
        assertThat(ASSIGNED_ANYCAST.needsOrgReference(), is(false));
        assertThat(EARLY_REGISTRATION.needsOrgReference(), is(false));
    }
}