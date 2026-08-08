import { Injectable } from "@nestjs/common";
import { idpPrisma, prisma } from "@kannan19302/database";

const BUILT_IN_TRANSLATIONS: Record<string, Record<string, string>> = {
  en: {},
  es: {
    "common.save": "Guardar",
    "common.cancel": "Cancelar",
    "common.delete": "Eliminar",
    "common.search": "Buscar",
    "common.loading": "Cargando...",
    "nav.dashboard": "Panel",
    "nav.finance": "Finanzas",
    "nav.hr": "Recursos Humanos",
    "nav.crm": "CRM",
    "nav.inventory": "Inventario",
  },
  fr: {
    "common.save": "Enregistrer",
    "common.cancel": "Annuler",
    "common.delete": "Supprimer",
    "common.search": "Rechercher",
    "common.loading": "Chargement...",
    "nav.dashboard": "Tableau de bord",
    "nav.finance": "Finance",
    "nav.hr": "Ressources Humaines",
    "nav.crm": "CRM",
    "nav.inventory": "Inventaire",
  },
  de: {
    "common.save": "Speichern",
    "common.cancel": "Abbrechen",
    "common.delete": "Löschen",
    "common.search": "Suchen",
    "common.loading": "Laden...",
    "nav.dashboard": "Armaturenbrett",
    "nav.finance": "Finanzen",
    "nav.hr": "Personalwesen",
    "nav.crm": "CRM",
    "nav.inventory": "Inventar",
  },
};

@Injectable()
export class I18nService {
  getSupportedLocales() {
    return [
      { code: "en", name: "English", direction: "ltr" },
      { code: "es", name: "Español", direction: "ltr" },
      { code: "fr", name: "Français", direction: "ltr" },
      { code: "de", name: "Deutsch", direction: "ltr" },
      { code: "ar", name: "العربية", direction: "rtl" },
      { code: "ja", name: "日本語", direction: "ltr" },
      { code: "zh", name: "中文", direction: "ltr" },
      { code: "hi", name: "हिन्दी", direction: "ltr" },
    ];
  }

  async getTranslations(
    locale: string,
    tenantId?: string,
  ): Promise<Record<string, string>> {
    const builtIn = BUILT_IN_TRANSLATIONS[locale] || {};

    if (tenantId) {
      const overrides = await prisma.languageOverride.findMany({
        where: { locale, tenantId },
      });
      const overrideMap: Record<string, string> = {};
      for (const o of overrides) {
        overrideMap[o.key] = o.translation;
      }
      return { ...builtIn, ...overrideMap };
    }

    return builtIn;
  }

  translate(
    key: string,
    locale: string,
    params?: Record<string, string>,
  ): string {
    const translations = BUILT_IN_TRANSLATIONS[locale] || {};
    let value = translations[key] || key;

    if (params) {
      for (const [k, v] of Object.entries(params)) {
        value = value.replace(`{{${k}}}`, v);
      }
    }

    return value;
  }

  async setOverride(
    tenantId: string,
    locale: string,
    key: string,
    value: string,
  ) {
    return prisma.languageOverride.upsert({
      where: { tenantId_locale_key: { tenantId, locale, key } },
      create: { tenantId, locale, key, translation: value },
      update: { translation: value },
    });
  }

  formatCurrency(amount: number, currency: string, locale: string): string {
    try {
      return new Intl.NumberFormat(locale, {
        style: "currency",
        currency,
      }).format(amount);
    } catch {
      return `${currency} ${amount.toFixed(2)}`;
    }
  }

  formatDate(
    date: Date,
    locale: string,
    style: "short" | "medium" | "long" = "medium",
  ): string {
    const options: Intl.DateTimeFormatOptions =
      style === "short"
        ? { year: "2-digit", month: "numeric", day: "numeric" }
        : style === "long"
          ? { year: "numeric", month: "long", day: "numeric", weekday: "long" }
          : { year: "numeric", month: "short", day: "numeric" };

    try {
      return new Intl.DateTimeFormat(locale, options).format(date);
    } catch {
      return date.toISOString().slice(0, 10);
    }
  }
}
