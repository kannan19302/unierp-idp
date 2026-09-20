import {
  Controller,
  Post,
  Req,
  UseGuards,
  BadRequestException,
} from "@nestjs/common";
import { ApiOperation, ApiTags } from "@nestjs/swagger";
import { InjectQueue } from "@nestjs/bullmq";
import { Queue } from "bullmq";
import { z } from "zod";
import { JwtAuthGuard } from "../guards/jwt-auth.guard";
import { RbacGuard } from "../guards/rbac.guard";
import { Permissions } from "../decorators/permissions.decorator";
import { ZodBody } from "../decorators/zod-body.decorator";
import { IDENTITY_EMAIL_QUEUE } from "../queues/queue.constants";
import { wrapEmailLayout } from "../email-templates/base-layout";

const testEmailSchema = z.object({
  to: z.string().email().optional(),
});

@ApiTags("platform-credentials")
@UseGuards(JwtAuthGuard, RbacGuard)
@Controller("admin/test-email")
export class TestEmailController {
  constructor(
    @InjectQueue(IDENTITY_EMAIL_QUEUE)
    private readonly emailQueue: Queue,
  ) {}

  @ApiOperation({ summary: "Send a test email using the currently active email provider" })
  @Permissions("admin.setting.update")
  @Post()
  async sendTestEmail(
    @ZodBody(testEmailSchema) dto: z.infer<typeof testEmailSchema>,
    @Req() req: any,
  ) {
    const recipient = dto.to || req.user?.email;
    if (!recipient) {
      throw new BadRequestException("No recipient email specified or available from user context");
    }

    const html = wrapEmailLayout({
      title: "Test Email: UniERP Platform Delivery",
      previewText: "Your UniERP email integration is functioning correctly",
      contentHtml: `
        <p style="margin: 0 0 16px 0;">Hello Administrator,</p>
        <p style="margin: 0 0 16px 0;">
          This is an automated verification email sent from your <strong>UniERP Platform Admin Console</strong> to confirm that outbound email delivery is properly configured.
        </p>
        <div style="background-color: #ecfdf5; border: 1px solid #a7f3d0; border-radius: 8px; padding: 14px 18px; margin: 20px 0; color: #065f46; font-size: 14px;">
          <strong>&#10003; Outbound Delivery Channel Verified</strong><br>
          Your platform credentials and API routing are operational.
        </div>
        <p style="margin: 0; color: #64748b; font-size: 13px;">
          Timestamp: ${new Date().toISOString()}<br>
          Requested by: ${req.user?.userId || "Admin"}
        </p>
      `,
      footerNotes: "This test was triggered by an authorized platform administrator.",
    });

    const job = await this.emailQueue.add(
      "send",
      {
        to: recipient,
        subject: "UniERP Integration Test: Email Channel Verified",
        body: html,
        tenantId: req.user?.tenantId || "platform",
        template: "test-email",
        isCanary: true,
      },
      {
        attempts: 2,
        removeOnComplete: 100,
        removeOnFail: 500,
      },
    );

    return {
      success: true,
      message: `Test email queued for delivery to ${recipient}`,
      recipient,
      jobId: job.id,
    };
  }
}
