import { exportReport } from "./handlers/reports";
import { requireAuth } from "./middleware";
router.get("/reports/export", requireAuth, exportReport);
