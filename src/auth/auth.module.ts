import { Module } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { JwtModule } from '@nestjs/jwt'
import { PassportModule } from '@nestjs/passport'
import { Env } from 'src/env'
import { AuthService } from './auth.service'

@Module({
  imports: [
    PassportModule,
    JwtModule.registerAsync({
      inject: [ConfigService],
      global: true,
      useFactory: (configService: ConfigService<Env, true>) => {
        const publicKey = configService.get<string>('JWT_PUBLIC_KEY', {
          infer: true,
        })
        const privateKey = configService.get<string>('JWT_PRIVATE_KEY', {
          infer: true,
        })
        return {
          signOptions: {
            algorithm: 'RS256',
          },

          privateKey: Buffer.from(privateKey, 'base64'),
          publicKey: Buffer.from(publicKey, 'base64'),
        }
      },
    }),
  ],
  providers: [AuthService],
})
export class AuthModule {}
