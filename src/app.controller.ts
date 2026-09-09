import { Controller, Get, Req, Res } from "@nestjs/common";
import type { Request, Response } from "express";
import { Public } from "./common/decorators/public.decorator";

@Controller()
export class AppController {
  @Get()
  @Public("Root platform redirect")
  root(@Req() req: Request, @Res() res: Response) {
    const defaultUrl =
      process.env.TENANT_APP_URL
        ? `${process.env.TENANT_APP_URL}/apps`
        : process.env.PLATFORM_WIZARD_URL || "http://localhost:4000";

    const token = req.cookies?.auth_token;
    if (token) {
      return res.redirect(defaultUrl);
    }
    return res.redirect("/oidc/login");
  }
}
