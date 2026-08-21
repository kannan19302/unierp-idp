import { Module } from "@nestjs/common";
import { AuthModule } from "./modules/auth/auth.module";
import { OidcModule } from "./modules/oidc/oidc.module";

@Module({
  imports: [AuthModule, OidcModule],
  controllers: [],
  providers: [],
})
export class AppModule {}
