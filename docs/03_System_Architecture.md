# System Architecture

```text
React (Vercel)
      |
 REST API
      |
Flask (Render)
   |        |
Supabase   ML Models
```

## Data Flow
1. User submits data.
2. Flask validates request.
3. Business logic executes.
4. Optional ML prediction.
5. Result stored in Supabase.
6. Response returned to frontend.
