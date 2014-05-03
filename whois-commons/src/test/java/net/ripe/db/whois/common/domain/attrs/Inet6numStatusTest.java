package net.ripe.db.whois.common.domain.attrs;


import net.ripe.db.whois.common.domain.CIString;
import org.junit.Test;

import static net.ripe.db.whois.common.domain.attrs.Inet6numStatus.*;
import static net.ripe.db.whois.common.domain.attrs.OrgType.*;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class Inet6numStatusTest {
    private final boolean HAS_RS_MAINTAINER = true;
    private final boolean HAS_NOT_RS_MAINTAINER = false;

    @Test
    public void requiresRsMaintainer() {
        assertThat(ASSIGNED_PA.requiresRsMaintainer(), is(false));
        assertThat(ALLOCATED_BY_RIR.requiresRsMaintainer(), is(true));
        assertThat(ASSIGNED_PI.requiresRsMaintainer(), is(true));
    }

    @Test
    public void requiresAllocMaintainer() {
        assertThat(ASSIGNED_PA.requiresAllocMaintainer(), is(false));
        assertThat(ALLOCATED_BY_RIR.requiresAllocMaintainer(), is(true));
        assertThat(ASSIGNED_PI.requiresAllocMaintainer(), is(false));
    }

    @Test
    public void worksWithParentStatus_assigned_pa() {
        assertThat(ASSIGNED_PA.worksWithParentStatus(ASSIGNED_PA, HAS_RS_MAINTAINER), is(false));
        assertThat(ASSIGNED_PA.worksWithParentStatus(ASSIGNED_PA, HAS_NOT_RS_MAINTAINER), is(false));

        assertThat(ASSIGNED_PA.worksWithParentStatus(ALLOCATED_BY_RIR, HAS_RS_MAINTAINER), is(true));
        assertThat(ASSIGNED_PA.worksWithParentStatus(ALLOCATED_BY_RIR, HAS_NOT_RS_MAINTAINER), is(true));

        assertThat(ASSIGNED_PA.worksWithParentStatus(ASSIGNED_PI, HAS_RS_MAINTAINER), is(false));
        assertThat(ASSIGNED_PA.worksWithParentStatus(ASSIGNED_PI, HAS_NOT_RS_MAINTAINER), is(false));
    }

    @Test
    public void worksWithParentStatus_allocated_by_rir() {
        assertThat(ALLOCATED_BY_RIR.worksWithParentStatus(ASSIGNED_PA, HAS_RS_MAINTAINER), is(false));
        assertThat(ALLOCATED_BY_RIR.worksWithParentStatus(ASSIGNED_PA, HAS_NOT_RS_MAINTAINER), is(false));

        assertThat(ALLOCATED_BY_RIR.worksWithParentStatus(ALLOCATED_BY_RIR, HAS_RS_MAINTAINER), is(false));
        assertThat(ALLOCATED_BY_RIR.worksWithParentStatus(ALLOCATED_BY_RIR, HAS_NOT_RS_MAINTAINER), is(false));

        assertThat(ALLOCATED_BY_RIR.worksWithParentStatus(ASSIGNED_PI, HAS_RS_MAINTAINER), is(false));
        assertThat(ALLOCATED_BY_RIR.worksWithParentStatus(ASSIGNED_PI, HAS_NOT_RS_MAINTAINER), is(false));
    }

    @Test
    public void worksWithParentStatus_assigned_pi() {
        assertThat(ASSIGNED_PI.worksWithParentStatus(ASSIGNED_PA, HAS_RS_MAINTAINER), is(false));
        assertThat(ASSIGNED_PI.worksWithParentStatus(ASSIGNED_PA, HAS_NOT_RS_MAINTAINER), is(false));

        assertThat(ASSIGNED_PI.worksWithParentStatus(ALLOCATED_BY_RIR, HAS_RS_MAINTAINER), is(false));
        assertThat(ASSIGNED_PI.worksWithParentStatus(ALLOCATED_BY_RIR, HAS_NOT_RS_MAINTAINER), is(false));

        assertThat(ASSIGNED_PI.worksWithParentStatus(ASSIGNED_PI, HAS_RS_MAINTAINER), is(false));
        assertThat(ASSIGNED_PI.worksWithParentStatus(ASSIGNED_PI, HAS_NOT_RS_MAINTAINER), is(false));
    }

    @Test
    public void needsOrgReference() {
        assertThat(ASSIGNED_PA.needsOrgReference(), is(false));
        assertThat(ALLOCATED_BY_RIR.needsOrgReference(), is(true));
        assertThat(ASSIGNED_PI.needsOrgReference(), is(true));
    }

    @Test
    public void getAllowedOrgTypes() {
        assertThat(ASSIGNED_PA.getAllowedOrgTypes(), containsInAnyOrder(LIR, OTHER));
        assertThat(ALLOCATED_BY_RIR.getAllowedOrgTypes(), containsInAnyOrder(IANA, RIR, LIR));
        assertThat(ASSIGNED_PI.getAllowedOrgTypes(), containsInAnyOrder(LIR, OTHER));
    }

    @Test
    public void isValidOrgType() {
        assertThat(ASSIGNED_PA.isValidOrgType(LIR), is(true));
        assertThat(ASSIGNED_PA.isValidOrgType(OTHER), is(true));
        assertThat(ASSIGNED_PA.isValidOrgType(IANA), is(false));
        assertThat(ASSIGNED_PA.isValidOrgType(RIR), is(false));

        assertThat(ALLOCATED_BY_RIR.isValidOrgType(LIR), is(true));
        assertThat(ALLOCATED_BY_RIR.isValidOrgType(OTHER), is(false));
        assertThat(ALLOCATED_BY_RIR.isValidOrgType(IANA), is(true));
        assertThat(ALLOCATED_BY_RIR.isValidOrgType(RIR), is(true));

        assertThat(ASSIGNED_PI.isValidOrgType(LIR), is(true));
        assertThat(ASSIGNED_PI.isValidOrgType(OTHER), is(true));
        assertThat(ASSIGNED_PI.isValidOrgType(IANA), is(false));
        assertThat(ASSIGNED_PI.isValidOrgType(RIR), is(false));
    }

    @Test
    public void getLiteralStatus() {
        assertThat(ASSIGNED_PA.getLiteralStatus(), is(CIString.ciString("ASSIGNED PA")));
        assertThat(ALLOCATED_BY_RIR.getLiteralStatus(), is(CIString.ciString("ALLOCATED-BY-RIR")));
        assertThat(ASSIGNED_PI.getLiteralStatus(), is(CIString.ciString("ASSIGNED PI")));
    }

    @Test
    public void getStatusFor() {
        assertThat(Inet6numStatus.getStatusFor(CIString.ciString("ASSIGNED PA")), is(ASSIGNED_PA));
        assertThat(Inet6numStatus.getStatusFor(CIString.ciString("ALLOCATED-BY-RIR")), is(ALLOCATED_BY_RIR));
        assertThat(Inet6numStatus.getStatusFor(CIString.ciString("ASSIGNED PI")), is(ASSIGNED_PI));

        try {
            Inet6numStatus.getStatusFor(CIString.ciString("AGGREGATED-BY-RIR"));
            fail();
        } catch (Exception expected) {}
    }
}
