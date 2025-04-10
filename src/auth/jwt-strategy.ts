import { ConfigService } from "@nestjs/config"
import { PassportStrategy } from "@nestjs/passport"
import { ExtractJwt, Strategy } from "passport-jwt"
import { z } from "zod"
import { Env } from "../env"
import { Injectable } from "@nestjs/common"

const tokenSchema = z.object({
  sub: z.string().uuid(),
})

export type UserPayload = z.infer<typeof tokenSchema>

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
 constructor(config: ConfigService<Env, true>) {
  const publicKey = config.get('JWT_PUBLIC_KEY', { infer: true })
  
  super({
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    // ignoreExpiration: false,
    secretOrKey: Buffer.from(publicKey, 'base64'),
    algorithms: ['RS256'],
    })
  }

  async validate(payload: UserPayload) {
    return tokenSchema.parse(payload)
  }
  
 }