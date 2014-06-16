package net.ripe.db.whois.update.handler.validator.domain;

import com.google.common.collect.Lists;
import net.ripe.db.whois.common.dao.RpslObjectDao;
import net.ripe.db.whois.common.dao.RpslObjectInfo;
import net.ripe.db.whois.common.domain.Ipv4Resource;
import net.ripe.db.whois.common.domain.Ipv6Resource;
import net.ripe.db.whois.common.iptree.*;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.update.domain.PreparedUpdate;
import net.ripe.db.whois.update.domain.UpdateContext;
import net.ripe.db.whois.update.domain.UpdateMessages;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.ArrayList;
import java.util.List;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class NoDashNotationIfDsRDataValidatorTest {
    @Mock
    PreparedUpdate update;
    @Mock
    UpdateContext updateContext;

    @InjectMocks
    NoDashNotationIfDsRDataValidator subject;

    @Test
    public void validate_range_succeeds() {

        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("" +
                "domain:         1-10.11.102.in-addr.arpa\n" +
                "descr:          Link Egypt A\n" +
                "admin-c:        MO35-AFRINIC\n" +
                "tech-c:         MO35-AFRINIC\n" +
                "zone-c:         MO35-AFRINIC\n" +
                "nserver:        michel.afrinic.net\n" +
                "mnt-by:         AFRINIC-HM-MNT\n" +
                "password:       afrinic\n" +
                "changed:        michel.odou@afrinic.net\n" +
                "source:         AFRINIC"));

        subject.validate(update, updateContext);
        verifyZeroInteractions(updateContext);
    }

    @Test
    public void validate_dsrdata_succeeds() {

        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("" +
                "domain:         10.11.102.in-addr.arpa\n" +
                "descr:          Link Egypt A\n" +
                "admin-c:        MO35-AFRINIC\n" +
                "tech-c:         MO35-AFRINIC\n" +
                "zone-c:         MO35-AFRINIC\n" +
                "ds-rdata:       ABCDEF0123456789\n" +
                "nserver:        michel.afrinic.net\n" +
                "mnt-by:         AFRINIC-HM-MNT\n" +
                "password:       afrinic\n" +
                "changed:        michel.odou@afrinic.net\n" +
                "source:         AFRINIC"));

        subject.validate(update, updateContext);
        verifyZeroInteractions(updateContext);
    }

    @Test
    public void validate_range_and_dsrdata_fails() {

        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("" +
                "domain:         1-10.11.102.in-addr.arpa\n" +
                "descr:          Link Egypt A\n" +
                "admin-c:        MO35-AFRINIC\n" +
                "tech-c:         MO35-AFRINIC\n" +
                "zone-c:         MO35-AFRINIC\n" +
                "ds-rdata:       ABCDEF0123456789\n" +
                "nserver:        michel.afrinic.net\n" +
                "mnt-by:         AFRINIC-HM-MNT\n" +
                "password:       afrinic\n" +
                "changed:        michel.odou@afrinic.net\n" +
                "source:         AFRINIC"));

        subject.validate(update, updateContext);
        verify(updateContext).addMessage(update, UpdateMessages.noDashNotationIfDsRData());
    }
}
