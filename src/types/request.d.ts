/* eslint-disable @typescript-eslint/no-empty-object-type */
import { Request } from 'express';

// ✅ Request dengan hanya body
export type TypedRequestBody<B> = Request<{}, {}, B>;

// ✅ Request dengan body + params
export type TypedRequestBodyParams<B, P> = Request<P, {}, B>;

// ✅ Request dengan body + query
export type TypedRequestBodyQuery<B, Q> = Request<{}, {}, B, Q>;

// ✅ Request lengkap: body + params + query
export type TypedRequestFull<B, P, Q> = Request<P, {}, B, Q>;

// ✅ Request dengan params (URL)
export type TypedRequestParams<P> = Request<P>;

// ✅ Request dengan query string
export type TypedRequestQuery<Q> = Request<{}, {}, {}, Q>;
