import {
  Controller,
  Get,
  Post,
  Param,
  Body,
  Query,
  UseGuards,
  Req,
  UploadedFile,
  UseInterceptors,
  BadRequestException,
} from "@nestjs/common";
import { FileInterceptor } from "@nestjs/platform-express";
import { TenantGuard } from "../guards/tenant.guard";
import { RbacGuard } from "../guards/rbac.guard";
import { Permissions } from "../decorators/permissions.decorator";
import { ImportService } from "../services/import.service";

interface AuthenticatedRequest {
  user: { tenantId: string; userId: string };
  tenantId?: string;
}

@Controller("import")
@UseGuards(TenantGuard, RbacGuard)
export class ImportController {
  constructor(private readonly importService: ImportService) {}

  @Post(":modelName/csv")
  @Permissions("import.create")
  @UseInterceptors(FileInterceptor("file"))
  async importCsv(
    @Param("modelName") modelName: string,
    @UploadedFile() file: Express.Multer.File,
    @Body()
    body: {
      skipDuplicates?: string;
      updateExisting?: string;
      batchSize?: string;
    },
    @Req() req: AuthenticatedRequest,
  ) {
    if (!file) {
      throw new BadRequestException("CSV file is required");
    }
    const tenantId = req.tenantId || req.user?.tenantId;
    const userId = req.user?.userId;
    return this.importService.importCsv(
      tenantId,
      userId,
      modelName,
      file.buffer,
      {
        skipDuplicates: body.skipDuplicates === "true",
        updateExisting: body.updateExisting === "true",
        batchSize: body.batchSize ? parseInt(body.batchSize, 10) : 100,
      },
    );
  }

  @Post(":modelName/xlsx")
  @Permissions("import.create")
  @UseInterceptors(FileInterceptor("file"))
  async importXlsx(
    @Param("modelName") modelName: string,
    @UploadedFile() file: Express.Multer.File,
    @Body()
    body: {
      skipDuplicates?: string;
      updateExisting?: string;
      batchSize?: string;
    },
    @Req() req: AuthenticatedRequest,
  ) {
    if (!file) {
      throw new BadRequestException("XLSX file is required");
    }
    const tenantId = req.tenantId || req.user?.tenantId;
    const userId = req.user?.userId;
    return this.importService.importXlsx(
      tenantId,
      userId,
      modelName,
      file.buffer,
      {
        skipDuplicates: body.skipDuplicates === "true",
        updateExisting: body.updateExisting === "true",
        batchSize: body.batchSize ? parseInt(body.batchSize, 10) : 100,
      },
    );
  }

  @Post(":modelName/json")
  @Permissions("import.create")
  async importJson(
    @Param("modelName") modelName: string,
    @Body()
    body: {
      data: any[];
      skipDuplicates?: boolean;
      updateExisting?: boolean;
      batchSize?: number;
    },
    @Req() req: AuthenticatedRequest,
  ) {
    const tenantId = req.tenantId || req.user?.tenantId;
    const userId = req.user?.userId;
    return this.importService.importJson(
      tenantId,
      userId,
      modelName,
      body.data,
      {
        skipDuplicates: body.skipDuplicates,
        updateExisting: body.updateExisting,
        batchSize: body.batchSize,
      },
    );
  }

  @Get("history")
  @Permissions("import.view")
  async getHistory(
    @Req() req: AuthenticatedRequest,
    @Query("page") page?: string,
    @Query("limit") limit?: string,
  ) {
    const tenantId = req.tenantId || req.user?.tenantId;
    return this.importService.getImportHistory(
      tenantId,
      page ? parseInt(page, 10) : 1,
      limit ? parseInt(limit, 10) : 20,
    );
  }

  @Get("history/:id")
  @Permissions("import.view")
  async getHistoryDetail(
    @Param("id") id: string,
    @Req() req: AuthenticatedRequest,
  ) {
    const tenantId = req.tenantId || req.user?.tenantId;
    return this.importService.getImportDetail(tenantId, id);
  }
}
