import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { User, Mail, Phone, Bell, Save } from "lucide-react";
import { useApiAuth } from "@/hooks/useApiAuth";
import { useToast } from "@/hooks/use-toast";
import { apiClient } from "@/lib/api";

interface UserProfile {
  id: string;
  user_id: string;
  full_name: string;
  receive_notifications: boolean;
  whatsapp?: string;
  created_at: string;
  updated_at: string;
}

export default function Profile() {
  const { user, signOut } = useApiAuth();
  const { toast } = useToast();
  
  const [formData, setFormData] = useState({
    full_name: "",
    whatsapp: "",
    receive_notifications: true,
  });
  const [saving, setSaving] = useState(false);

  // Initialize form with user data
  useEffect(() => {
    if (user) {
      setFormData({
        full_name: user.full_name || "",
        whatsapp: "", // This would need to be implemented in PHP backend
        receive_notifications: true,
      });
    }
  }, [user]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    
    try {
      await apiClient.updateProfile(formData);
      toast({
        title: "Perfil atualizado",
        description: "Suas informações foram salvas com sucesso!",
      });
    } catch (error: any) {
      toast({
        title: "Erro",
        description: `Erro ao atualizar perfil: ${error.message}`,
        variant: "destructive",
      });
    } finally {
      setSaving(false);
    }
  };

  const handleSignOut = async () => {
    const { error } = await signOut();
    if (error) {
      toast({
        title: "Erro",
        description: "Erro ao fazer logout",
        variant: "destructive",
      });
    }
  };

  return (
    <div className="space-y-6 max-w-2xl">
      <div>
        <h1 className="text-3xl font-bold">Meu Perfil</h1>
        <p className="text-muted-foreground">
          Gerencie suas informações pessoais e preferências
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <User className="h-5 w-5" />
            Informações Pessoais
          </CardTitle>
          <CardDescription>
            Atualize seus dados pessoais e de contato
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="full_name">Nome Completo</Label>
              <Input
                id="full_name"
                value={formData.full_name}
                onChange={(e) => setFormData(prev => ({ ...prev, full_name: e.target.value }))}
                placeholder="Seu nome completo"
                required
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                value={user?.email || ""}
                disabled
                className="bg-muted"
              />
              <p className="text-sm text-muted-foreground">
                O email não pode ser alterado através do perfil
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="whatsapp">WhatsApp</Label>
              <Input
                id="whatsapp"
                value={formData.whatsapp}
                onChange={(e) => setFormData(prev => ({ ...prev, whatsapp: e.target.value }))}
                placeholder="(11) 99999-9999"
              />
            </div>

            <Separator />

            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label className="flex items-center gap-2">
                    <Bell className="h-4 w-4" />
                    Receber Notificações
                  </Label>
                  <p className="text-sm text-muted-foreground">
                    Receba notificações sobre novos arquivos e atualizações
                  </p>
                </div>
                <Switch
                  checked={formData.receive_notifications}
                  onCheckedChange={(checked) => 
                    setFormData(prev => ({ ...prev, receive_notifications: checked }))
                  }
                />
              </div>
            </div>

            <div className="flex gap-4 pt-4">
              <Button type="submit" disabled={saving}>
                <Save className="h-4 w-4 mr-2" />
                {saving ? "Salvando..." : "Salvar Alterações"}
              </Button>
              
              <Button type="button" variant="outline" onClick={handleSignOut}>
                Sair
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Informações da Conta</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          <div className="flex justify-between">
            <span className="text-muted-foreground">Conta criada em:</span>
            <span>Não disponível</span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">Última atualização:</span>
            <span>Não disponível</span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">ID do usuário:</span>
            <span className="font-mono text-sm">{user?.id?.slice(0, 8)}...</span>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}