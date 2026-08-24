import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  Header,
  Post,
  Query,
  Req,
  Res,
  UseGuards,
} from "@nestjs/common";
import { ApiExcludeController } from "@nestjs/swagger";
import { Throttle } from "@nestjs/throttler";
import type { Request, Response } from "express";
import { JwtAuthGuard } from "../../../common/guards/jwt-auth.guard";
import { AccountContactService } from "../../auth/account-contact.service";
import { verifyCsrf } from "./login.controller";

type AccountRequest = Request & {
  user?: { userId?: string; tenantId?: string; sid?: string };
};

@ApiExcludeController()
@Controller("oidc/account/contact")
export class AccountContactController {
  constructor(private readonly contacts: AccountContactService) {}

  @Post("add")
  @Header("Cache-Control", "no-store")
  @UseGuards(JwtAuthGuard)
  @Throttle({ default: { limit: 5, ttl: 60 * 60_000 } })
  async add(@Body() body: Record<string, unknown>, @Req() req: AccountRequest) {
    this.assertCsrf(req, body._csrf);
    return this.contacts.addRecoveryEmail({
      userId: req.user?.userId || "",
      tenantId: req.user?.tenantId || "",
      sid: req.user?.sid || "",
      email: typeof body.email === "string" ? body.email : "",
      label: typeof body.label === "string" ? body.label : undefined,
    });
  }

  @Post("resend")
  @Header("Cache-Control", "no-store")
  @UseGuards(JwtAuthGuard)
  @Throttle({ default: { limit: 5, ttl: 60 * 60_000 } })
  async resend(@Body() body: Record<string, unknown>, @Req() req: AccountRequest) {
    this.assertCsrf(req, body._csrf);
    return this.contacts.resendVerification({
      userId: req.user?.userId || "",
      tenantId: req.user?.tenantId || "",
      sid: req.user?.sid || "",
      contactId: typeof body.contactId === "string" ? body.contactId : "",
    });
  }

  @Post("remove")
  @Header("Cache-Control", "no-store")
  @UseGuards(JwtAuthGuard)
  @Throttle({ default: { limit: 10, ttl: 60 * 60_000 } })
  async remove(@Body() body: Record<string, unknown>, @Req() req: AccountRequest) {
    this.assertCsrf(req, body._csrf);
    return this.contacts.remove({
      userId: req.user?.userId || "",
      tenantId: req.user?.tenantId || "",
      sid: req.user?.sid || "",
      contactId: typeof body.contactId === "string" ? body.contactId : "",
    });
  }

  @Get("verify")
  @Header("Cache-Control", "no-store")
  @Throttle({ default: { limit: 20, ttl: 60_000 } })
  async verify(@Query("token") token: string, @Res() res: Response) {
    try {
      await this.contacts.verify(token || "");
      res.redirect(302, "/oidc/login?success=Recovery%20email%20verified.%20Sign%20in%20to%20continue.");
    } catch {
      res.redirect(302, "/oidc/login?error=Verification%20link%20is%20invalid%20or%20expired.");
    }
  }

  private assertCsrf(req: Request, value: unknown): void {
    if (!verifyCsrf(req, typeof value === "string" ? value : undefined)) {
      throw new ForbiddenException("Invalid or expired security token.");
    }
  }
}
