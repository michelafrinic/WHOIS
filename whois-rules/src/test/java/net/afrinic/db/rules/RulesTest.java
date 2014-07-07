package net.afrinic.db.rules;

import net.ripe.db.whois.common.rpsl.AttributeTemplate;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.ObjectTemplate;
import net.ripe.db.whois.common.rpsl.ObjectType;
import org.junit.Assert;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

/**
 * Created by yogesh on 4/4/14.
 *
 * @see http://maven.apache.org/surefire/maven-surefire-plugin/examples/junit.html
 */
@RunWith(MockitoJUnitRunner.class)
public class RulesTest {

    private final WhoisRules whoisRulesUnderTest = new WhoisRules();

    @Test
    public void rpslTemplateCheck() {

        ObjectTemplate[] objectTemplates = ObjectTemplateBuilder.buildObjectTemplateArray(whoisRulesUnderTest);

        for (ObjectTemplate objectTemplate: objectTemplates) {
            System.out.println();
            System.out.println(objectTemplate);
        }

        for (ObjectTemplate objectTemplate: objectTemplates) {
            Assert.assertTrue(objectTemplate.getAllAttributes().size() > 1);
        }

    }

    @Test
    @Category(ExampleTestGroup.class)
    public void examplePersonObjectTemplate() {
        AttributeTemplate personEmail = null;
        AttributeTemplate personMntBy = null;

        AttributeTemplate[] attributeTemplates = whoisRulesUnderTest.getAttributeTemplates();


        for (AttributeTemplate attributeTemplate: attributeTemplates) {
            if (ObjectType.PERSON.equals(attributeTemplate.getObjectType()))  {
                if (AttributeType.E_MAIL.equals(attributeTemplate.getAttributeType())) {
                    personEmail = attributeTemplate;

                } else if (AttributeType.MNT_BY.equals(attributeTemplate.getAttributeType())) {
                    personMntBy = attributeTemplate;
                }
            }
        }
        Assert.assertEquals(AttributeTemplate.Requirement.MANDATORY, personEmail.getRequirement());
        Assert.assertEquals(AttributeTemplate.Requirement.OPTIONAL, personMntBy.getRequirement());
    }

    @Test
    @Category(AfrinicTestGroup.class)
    public void afrinicPersonObjectTemplate() {
        AttributeTemplate personEmail = null;
        AttributeTemplate personMntBy = null;

        AttributeTemplate[] attributeTemplates = whoisRulesUnderTest.getAttributeTemplates();


        for (AttributeTemplate attributeTemplate: attributeTemplates) {
            if (ObjectType.PERSON.equals(attributeTemplate.getObjectType()))  {
                if (AttributeType.E_MAIL.equals(attributeTemplate.getAttributeType())) {
                    personEmail = attributeTemplate;

                } else if (AttributeType.MNT_BY.equals(attributeTemplate.getAttributeType())) {
                    personMntBy = attributeTemplate;
                }
            }
        }
        Assert.assertEquals(AttributeTemplate.Requirement.MANDATORY, personEmail.getRequirement());
        Assert.assertEquals(AttributeTemplate.Requirement.OPTIONAL, personMntBy.getRequirement());
    }

    @Test
    @Category(RipeTestGroup.class)
    public void ripePersonObjectTemplate() {
        AttributeTemplate personEmail = null;
        AttributeTemplate personMntBy = null;

        AttributeTemplate[] attributeTemplates = whoisRulesUnderTest.getAttributeTemplates();


        for (AttributeTemplate attributeTemplate: attributeTemplates) {
            if (ObjectType.PERSON.equals(attributeTemplate.getObjectType()))  {
                if (AttributeType.E_MAIL.equals(attributeTemplate.getAttributeType())) {
                    personEmail = attributeTemplate;

                } else if (AttributeType.MNT_BY.equals(attributeTemplate.getAttributeType())) {
                    personMntBy = attributeTemplate;
                }
            }
        }
        Assert.assertEquals(AttributeTemplate.Requirement.OPTIONAL, personEmail.getRequirement());
        Assert.assertEquals(AttributeTemplate.Requirement.MANDATORY, personMntBy.getRequirement());
    }

}
