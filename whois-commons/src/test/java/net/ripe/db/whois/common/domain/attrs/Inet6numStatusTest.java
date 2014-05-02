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
        assertThat(AGGREGATED_BY_LIR.requiresRsMaintainer(), is(false));
        assertThat(ALLOCATED_BY_RIR.requiresRsMaintainer(), is(true));
        assertThat(ASSIGNED_PI.requiresRsMaintainer(), is(true));
    }

    @Test
    public void requiresAllocMaintainer() {
        assertThat(AGGREGATED_BY_LIR.requiresAllocMaintainer(), is(false));
        assertThat(ALLOCATED_BY_RIR.requiresAllocMaintainer(), is(true));
        assertThat(ASSIGNED_PI.requiresAllocMaintainer(), is(false));
    }

    @Test
    public void worksWithParentStatus_aggregated_by_lir() {
        assertThat(AGGREGATED_BY_LIR.worksWithParentStatus(AGGREGATED_BY_LIR, HAS_RS_MAINTAINER), is(false));
        assertThat(AGGREGATED_BY_LIR.worksWithParentStatus(AGGREGATED_BY_LIR, HAS_NOT_RS_MAINTAINER), is(false));

        assertThat(AGGREGATED_BY_LIR.worksWithParentStatus(ALLOCATED_BY_RIR, HAS_RS_MAINTAINER), is(true));
        assertThat(AGGREGATED_BY_LIR.worksWithParentStatus(ALLOCATED_BY_RIR, HAS_NOT_RS_MAINTAINER), is(true));

        assertThat(AGGREGATED_BY_LIR.worksWithParentStatus(ASSIGNED_PI, HAS_RS_MAINTAINER), is(false));
        assertThat(AGGREGATED_BY_LIR.worksWithParentStatus(ASSIGNED_PI, HAS_NOT_RS_MAINTAINER), is(false));
    }

    @Test
    public void worksWithParentStatus_allocated_by_rir() {
        assertThat(ALLOCATED_BY_RIR.worksWithParentStatus(AGGREGATED_BY_LIR, HAS_RS_MAINTAINER), is(false));
        assertThat(ALLOCATED_BY_RIR.worksWithParentStatus(AGGREGATED_BY_LIR, HAS_NOT_RS_MAINTAINER), is(false));

        assertThat(ALLOCATED_BY_RIR.worksWithParentStatus(ALLOCATED_BY_RIR, HAS_RS_MAINTAINER), is(false));
        assertThat(ALLOCATED_BY_RIR.worksWithParentStatus(ALLOCATED_BY_RIR, HAS_NOT_RS_MAINTAINER), is(false));

        assertThat(ALLOCATED_BY_RIR.worksWithParentStatus(ASSIGNED_PI, HAS_RS_MAINTAINER), is(false));
        assertThat(ALLOCATED_BY_RIR.worksWithParentStatus(ASSIGNED_PI, HAS_NOT_RS_MAINTAINER), is(false));
    }

    @Test
    public void worksWithParentStatus_assigned_pi() {
        assertThat(ASSIGNED_PI.worksWithParentStatus(AGGREGATED_BY_LIR, HAS_RS_MAINTAINER), is(false));
        assertThat(ASSIGNED_PI.worksWithParentStatus(AGGREGATED_BY_LIR, HAS_NOT_RS_MAINTAINER), is(false));

        assertThat(ASSIGNED_PI.worksWithParentStatus(ALLOCATED_BY_RIR, HAS_RS_MAINTAINER), is(false));
        assertThat(ASSIGNED_PI.worksWithParentStatus(ALLOCATED_BY_RIR, HAS_NOT_RS_MAINTAINER), is(false));

        assertThat(ASSIGNED_PI.worksWithParentStatus(ASSIGNED_PI, HAS_RS_MAINTAINER), is(false));
        assertThat(ASSIGNED_PI.worksWithParentStatus(ASSIGNED_PI, HAS_NOT_RS_MAINTAINER), is(false));
    }

    @Test
    public void needsOrgReference() {
        assertThat(AGGREGATED_BY_LIR.needsOrgReference(), is(false));
        assertThat(ALLOCATED_BY_RIR.needsOrgReference(), is(true));
        assertThat(ASSIGNED_PI.needsOrgReference(), is(true));
    }

    @Test
    public void getAllowedOrgTypes() {
        assertThat(AGGREGATED_BY_LIR.getAllowedOrgTypes(), containsInAnyOrder(LIR, OTHER));
        assertThat(ALLOCATED_BY_RIR.getAllowedOrgTypes(), containsInAnyOrder(IANA, RIR, LIR));
        assertThat(ASSIGNED_PI.getAllowedOrgTypes(), containsInAnyOrder(LIR, OTHER));
    }

    @Test
    public void isValidOrgType() {
        assertThat(AGGREGATED_BY_LIR.isValidOrgType(LIR), is(true));
        assertThat(AGGREGATED_BY_LIR.isValidOrgType(OTHER), is(true));
        assertThat(AGGREGATED_BY_LIR.isValidOrgType(IANA), is(false));
        assertThat(AGGREGATED_BY_LIR.isValidOrgType(RIR), is(false));

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
        assertThat(AGGREGATED_BY_LIR.getLiteralStatus(), is(CIString.ciString("ASSIGNED PA")));
        assertThat(ALLOCATED_BY_RIR.getLiteralStatus(), is(CIString.ciString("ALLOCATED-BY-RIR")));
        assertThat(ASSIGNED_PI.getLiteralStatus(), is(CIString.ciString("ASSIGNED PI")));
    }

    @Test
    public void getStatusFor() {
        assertThat(Inet6numStatus.getStatusFor(CIString.ciString("ASSIGNED PA")), is(AGGREGATED_BY_LIR));
        assertThat(Inet6numStatus.getStatusFor(CIString.ciString("ALLOCATED-BY-RIR")), is(ALLOCATED_BY_RIR));
        assertThat(Inet6numStatus.getStatusFor(CIString.ciString("ASSIGNED PI")), is(ASSIGNED_PI));

        try {
            Inet6numStatus.getStatusFor(CIString.ciString("AGGREGATED-BY-RIR"));
            fail();
        } catch (Exception expected) {}
    }
}
