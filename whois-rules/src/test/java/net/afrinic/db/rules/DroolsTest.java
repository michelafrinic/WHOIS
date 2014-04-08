package net.afrinic.db.rules;

import net.ripe.db.whois.common.rpsl.AttributeTemplate;
import net.ripe.db.whois.common.rpsl.ObjectTemplate;
import net.ripe.db.whois.common.rpsl.ObjectType;
import org.drools.KnowledgeBase;
import org.drools.KnowledgeBaseFactory;
import org.drools.builder.KnowledgeBuilder;
import org.drools.builder.KnowledgeBuilderFactory;
import org.drools.builder.ResourceType;
import org.drools.definition.KnowledgePackage;
import org.drools.definition.rule.Rule;
import org.drools.io.ResourceFactory;
import org.drools.runtime.StatefulKnowledgeSession;
import org.junit.Assert;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static net.ripe.db.whois.common.rpsl.AttributeType.*;
import static net.ripe.db.whois.common.rpsl.AttributeTemplate.Requirement.*;
import static net.ripe.db.whois.common.rpsl.AttributeTemplate.Cardinality.*;
import static net.ripe.db.whois.common.rpsl.AttributeTemplate.Key.*;

import java.io.File;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Iterator;

/**
 * Created by michel on 4/7/14.
 */
public class DroolsTest {
    private static final String RESOURCE_FILE = "afrinic.drl";

    private static KnowledgeBase createKnowledgeBase() {
        String resourceName = System.getProperty("drools.rules.file");
        KnowledgeBuilder builder = KnowledgeBuilderFactory.newKnowledgeBuilder();

        //Add drl file into builder
        URL fileURL = Thread.currentThread().getContextClassLoader().getResource((resourceName != null && !"".equals(resourceName)) ? resourceName : RESOURCE_FILE);
        File drl = null;
        try {
            drl = new File(fileURL.toURI());
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }

        builder.add(ResourceFactory.newFileResource(drl), ResourceType.DRL);
        if (builder.hasErrors()) {
            throw new RuntimeException(builder.getErrors().toString());
        }

        KnowledgeBase knowledgeBase = KnowledgeBaseFactory.newKnowledgeBase();
        //Add to Knowledge Base packages from the builder which are actually the rules from the drl file.
        knowledgeBase.addKnowledgePackages(builder.getKnowledgePackages());

        return knowledgeBase;
    }

    @Test
    @Category(AfrinicTestGroup.class)
    public void testAfrinic() {
        //Create KnowledgeBase...
        KnowledgeBase knowledgeBase = createKnowledgeBase();
        //Create a stateful session
        StatefulKnowledgeSession session = knowledgeBase.newStatefulKnowledgeSession();
        try {

            //Create Facts and insert them
            ObjectTemplate objectTemplatePerson = new ObjectTemplate();
            objectTemplatePerson.setObjectType(ObjectType.PERSON);

            objectTemplatePerson.setAttributeTemplates(new AttributeTemplate(PERSON, MANDATORY, SINGLE, LOOKUP_KEY));

            session.insert(objectTemplatePerson);
            session.fireAllRules();

            AttributeTemplate email = objectTemplatePerson.getAttributeTemplate(E_MAIL);
            AttributeTemplate mntBy = objectTemplatePerson.getAttributeTemplate(MNT_BY);

            Assert.assertNotNull(email);
            Assert.assertNotNull(mntBy);

            Assert.assertEquals(AttributeTemplate.Requirement.MANDATORY, email.getRequirement());
            Assert.assertEquals(AttributeTemplate.Requirement.OPTIONAL, mntBy.getRequirement());

        } finally {
            session.dispose();
        }
    }

    @Test
    @Category(RipeTestGroup.class)
    public void testRipe() {
        //Create KnowledgeBase...
        KnowledgeBase knowledgeBase = createKnowledgeBase();
        //Create a stateful session
        StatefulKnowledgeSession session = knowledgeBase.newStatefulKnowledgeSession();
        try {

            //Create Facts and insert them
            ObjectTemplate objectTemplatePerson = new ObjectTemplate();
            objectTemplatePerson.setObjectType(ObjectType.PERSON);

            objectTemplatePerson.setAttributeTemplates(new AttributeTemplate(PERSON, MANDATORY, SINGLE, LOOKUP_KEY));

            session.insert(objectTemplatePerson);
            session.fireAllRules();

            AttributeTemplate email = objectTemplatePerson.getAttributeTemplate(E_MAIL);
            AttributeTemplate mntBy = objectTemplatePerson.getAttributeTemplate(MNT_BY);

            Assert.assertNotNull(email);
            Assert.assertNotNull(mntBy);

            Assert.assertEquals(AttributeTemplate.Requirement.OPTIONAL, email.getRequirement());
            Assert.assertEquals(AttributeTemplate.Requirement.MANDATORY, mntBy.getRequirement());

        } finally {
            session.dispose();
        }
    }

}
