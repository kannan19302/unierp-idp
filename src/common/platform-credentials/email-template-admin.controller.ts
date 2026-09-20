import {
  Controller,
  Get,
  Post,
  Param,
  UseGuards,
  NotFoundException,
} from "@nestjs/common";
import { ApiOperation, ApiTags } from "@nestjs/swagger";
import { z } from "zod";
import { JwtAuthGuard } from "../guards/jwt-auth.guard";
import { RbacGuard } from "../guards/rbac.guard";
import { Permissions } from "../decorators/permissions.decorator";
import { ZodBody } from "../decorators/zod-body.decorator";
import {
  SYSTEM_EMAIL_TEMPLATES,
  renderEmailTemplate,
  SystemEmailTemplateKey,
} from "../email-templates";

const previewSchema = z.object({
  variables: z.record(z.string(), z.any()).optional(),
});

@ApiTags("platform-credentials")
@UseGuards(JwtAuthGuard, RbacGuard)
@Controller("admin/email-templates")
export class EmailTemplateAdminController {
  @ApiOperation({ summary: "List all system email templates with sample data" })
  @Permissions("admin.setting.read")
  @Get()
  async listTemplates() {
    return SYSTEM_EMAIL_TEMPLATES.map((tmpl) => {
      const rendered = renderEmailTemplate(tmpl.key, tmpl.sampleVariables);
      return {
        key: tmpl.key,
        name: tmpl.name,
        description: tmpl.description,
        category: tmpl.category,
        sampleVariables: tmpl.sampleVariables,
        defaultSubject: rendered.subject,
        previewHtml: rendered.html,
      };
    });
  }

  @ApiOperation({ summary: "Preview a system email template with custom variables" })
  @Permissions("admin.setting.read")
  @Post(":key/preview")
  async previewTemplate(
    @Param("key") key: string,
    @ZodBody(previewSchema) dto: z.infer<typeof previewSchema>,
  ) {
    const meta = SYSTEM_EMAIL_TEMPLATES.find((t) => t.key === key);
    if (!meta) {
      throw new NotFoundException(`Unknown email template: "${key}"`);
    }

    const vars = {
      ...meta.sampleVariables,
      ...(dto.variables || {}),
    };

    const rendered = renderEmailTemplate(key as SystemEmailTemplateKey, vars);
    return {
      key,
      name: meta.name,
      subject: rendered.subject,
      html: rendered.html,
      text: rendered.text,
      variablesUsed: vars,
    };
  }
}
