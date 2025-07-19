// src/utils/loggerUtils.ts
export const sanitizePayload = (payloadStr: null | string): null | string => {
    if (!payloadStr) return null;

    try {
        const obj = JSON.parse(payloadStr);

        const sensitiveKeys = ['password', 'token', 'otp', 'secret'];
        for (const key of sensitiveKeys) {
            if (obj.hasOwnProperty(key)) {
                obj[key] = '[FILTERED]';
            }
        }

        return JSON.stringify(obj);
    } catch (err) {
        return payloadStr; // fallback kalau bukan JSON
    }
};
